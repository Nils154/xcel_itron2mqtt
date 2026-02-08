import os
import ssl
import yaml
import json
import requests
import logging
import paho.mqtt.client as mqtt
import xml.etree.ElementTree as ET
from time import sleep
from pathlib import Path
from typing import Tuple
#from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from requests.adapters import HTTPAdapter
from tenacity import retry, stop_after_attempt, before_sleep_log, wait_exponential
import urllib3

# Suppress InsecureRequestWarning for verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Local imports
from xcelEndpoint import xcelEndpoint

# Get the directory where this script is located
_SCRIPT_DIR = Path(__file__).parent

IEEE_PREFIX = '{urn:ieee:std:2030.5:ns}'
# Our target cipher is: ECDHE-ECDSA-AES128-CCM8
# Security level 0 is required to allow CCM8 ciphers in OpenSSL 3.x
CIPHERS = 'ECDHE-ECDSA-AES128-CCM8:@SECLEVEL=0'

logger = logging.getLogger(__name__)

# Enable verbose SSL/TLS debugging
# Uncomment these lines to see detailed SSL handshake information
# logging.getLogger('urllib3').setLevel(logging.DEBUG)
# import http.client
# http.client.HTTPConnection.debuglevel = 1

# Create an adapter for our request to enable the non-standard cipher
# From https://lukasa.co.uk/2017/02/Configuring_TLS_With_Requests/
class CCM8Adapter(HTTPAdapter):
    """
    A TransportAdapter that re-enables ECDHE support in Requests.
    Not really sure how much redundancy is actually required here
    """
    def __init__(self, cert_file=None, key_file=None, *args, **kwargs):
        self.cert_file = cert_file
        self.key_file = key_file
        super(CCM8Adapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.create_ssl_context()
        return super(CCM8Adapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs['ssl_context'] = self.create_ssl_context()
        return super(CCM8Adapter, self).proxy_manager_for(*args, **kwargs)

    def create_ssl_context(self):
        # Create SSL context with TLSv1.2
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

        # Disable hostname checking and set verify mode
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Changed from CERT_REQUIRED since we're using verify=False anyway

        # Set the specific cipher WITH @SECLEVEL=0
        # The @SECLEVEL=0 is critical - it sets the OpenSSL security level to 0,
        # which is required to allow CCM8 ciphers in OpenSSL 3.x
        context.set_ciphers(CIPHERS)
        logger.debug(f"Set ciphers with security level 0 (current security_level: {context.security_level})")

        # Load client certificate if provided
        if self.cert_file and self.key_file:
            try:
                context.load_cert_chain(self.cert_file, self.key_file)
                logger.debug(f"Loaded client certificate: {self.cert_file}")
            except Exception as e:
                logger.error(f"Failed to load client certificate: {e}")
        else:
            logger.warning(f"No client certificate provided to SSL context")

        # Enable legacy renegotiation for devices that don't support RFC 5746
        # Required for Itron meters with OpenSSL 3.x
        context.options |= ssl.OP_LEGACY_SERVER_CONNECT

        # Disable various modern TLS features that might cause issues
        context.options |= ssl.OP_NO_COMPRESSION
        if hasattr(ssl, 'OP_NO_TLSv1_3'):
            context.options |= ssl.OP_NO_TLSv1_3  # Disable TLS 1.3

        # Debug logging to verify SSL context configuration
        logger.debug(f"SSL Context created with:")
        logger.debug(f"  Protocol: TLSv1.2")
        logger.debug(f"  Ciphers: ECDHE-ECDSA-AES128-CCM8")
        logger.debug(f"  Legacy renegotiation: enabled (OP_LEGACY_SERVER_CONNECT)")
        logger.debug(f"  Verify mode: {context.verify_mode}")
        logger.debug(f"  Check hostname: {context.check_hostname}")
        logger.debug(f"  Options: {hex(context.options)}")

        return context

class xcelMeter():

    def __init__(self, name: str, ip_address: str, port: int, creds: Tuple[str, str]):
        self.name = name
        self.POLLING_RATE = 5.0
        # Base URL used to query the meter
        self.url = f'https://{ip_address}:{port}'

        # Setup the MQTT server connection
        self.mqtt_server_address = os.getenv('MQTT_SERVER')
        self.mqtt_port = self.get_mqtt_port()
        self.mqtt_client = self.setup_mqtt(self.mqtt_server_address, self.mqtt_port)

        # Create a new requests session based on the passed in ip address and port #
        self.requests_session = self.setup_session(creds, ip_address)

        # Set to uninitialized
        self.initalized = False

    @retry(stop=stop_after_attempt(15),
           wait=wait_exponential(multiplier=1, min=1, max=15),
           before_sleep=before_sleep_log(logger, logging.WARNING),
           reraise=True)
    def setup(self) -> None:
        # XML Entries we're looking for within the endpoint
        hw_info_names = ['lFDI', 'swVer', 'mfID']
        # Endpoint of the meter used for HW info
        hw_info_url = '/sdev/sdi'
        # Query the meter to get some more details about it
        details_dict = self.get_hardware_details(hw_info_url, hw_info_names)
        self._mfid = details_dict['mfID']
        self._lfdi = details_dict['lFDI']
        self._swVer = details_dict['swVer']

        # Device info used for home assistant MQTT discovery
        self.device_info = {
                            "device": {
                                "identifiers": [self._lfdi],
                                "name": self.name,
                                "model": self._mfid,
                                "sw_version": self._swVer
                                }
                            }
        # Send homeassistant a new device config for the meter
        self.send_mqtt_config()
        # The swVer will dictate which version of endpoints we use
        # Convert swVer to file version format (e.g., "3.2.50" -> "3_2_50")
        swver_file_format = str(self._swVer).replace('.', '_')
        versioned_config_path = _SCRIPT_DIR / 'configs' / f'endpoints_{swver_file_format}.yaml'
        default_config_path = _SCRIPT_DIR / 'configs' / 'endpoints_default.yaml'
        
        # Check if version-specific endpoints file exists, otherwise use default
        if versioned_config_path.exists():
            endpoints_file_ver = swver_file_format
            config_path = versioned_config_path
        else:
            endpoints_file_ver = 'default'
            config_path = default_config_path
        
        logger.info(f"Software version: {self._swVer}")
        logger.info(f"Endpoints file version: {endpoints_file_ver}")

        # List to store our endpoint objects in
        self.endpoints_list = self.load_endpoints(str(config_path))

        # create endpoints from list
        self.endpoints = self.create_endpoints(self.endpoints_list, self.device_info)

        # ready to go
        self.initalized = True

    def generate_endpoints_from_tree(self, save_file: bool = True) -> list:
        """
        Uses map_upt_tree to discover all available meter readings and generates
        an endpoints YAML file based on the discovered structure.
        
        Args:
            save_file: If True, saves the generated endpoints to a YAML file (default: True)
            
        Returns:
            list: List of endpoint dictionaries in the same format as loaded from YAML
        """
        logger.info("Starting UPT tree mapping to discover endpoints...")
        
        # Get the full UPT tree
        upt_tree = self.map_upt_tree(pretty_print=False)
        
        # Find all MeterReading entries in the tree
        endpoints = []
        
        # Navigate to the MeterReading list
        try:
            usage_point = upt_tree.get('UsagePoint', {})
            if isinstance(usage_point, dict):
                # Try _linked_content first
                linked = usage_point.get('_linked_content', {})
                if not linked and isinstance(usage_point, dict):
                    linked = usage_point
                
                meter_reading_list_link = linked.get('MeterReadingListLink', {})
                if isinstance(meter_reading_list_link, dict):
                    mrl_linked = meter_reading_list_link.get('_linked_content', {})
                    if isinstance(mrl_linked, dict):
                        # Get the _all_items list
                        all_items = mrl_linked.get('_all_items', [])
                        
                        if not all_items and isinstance(mrl_linked, dict):
                            # Try to find items directly in the structure
                            for key, value in mrl_linked.items():
                                if isinstance(value, list) and key != '_attributes':
                                    all_items = value
                                    break
                        
                        logger.info(f"Found {len(all_items)} meter readings in tree")
                        
                        # Process each meter reading
                        for item in all_items:
                            if not isinstance(item, dict):
                                continue
                            
                            # Get description
                            description = item.get('description', '')
                            if isinstance(description, dict):
                                description = description.get('_value', '')
                            
                            if not description:
                                continue
                            
                            # Determine URL - prefer ReadingSetListLink over ReadingLink
                            final_url = None
                            reading_type_info = {}
                            
                            # Check for ReadingSetListLink first (for historical/interval data)
                            reading_set_link = item.get('ReadingSetListLink', {})
                            if isinstance(reading_set_link, dict):
                                rs_attrs = reading_set_link.get('_attributes', {})
                                if rs_attrs:
                                    rs_href = rs_attrs.get('href', '')
                                    if rs_href:
                                        # Construct URL to first reading in first reading set
                                        final_url = f"{rs_href}/1/r/1"
                            
                            # Fall back to ReadingLink (for current readings)
                            if not final_url:
                                reading_link = item.get('ReadingLink', {})
                                if isinstance(reading_link, dict):
                                    rl_attrs = reading_link.get('_attributes', {})
                                    if rl_attrs:
                                        final_url = rl_attrs.get('href', '')
                            
                            if not final_url:
                                logger.warning(f"No URL found for {description}, skipping")
                                continue
                            
                            # Get ReadingTypeLink info to determine device class and unit
                            reading_type_link = item.get('ReadingTypeLink', {})
                            if isinstance(reading_type_link, dict):
                                rt_linked = reading_type_link.get('_linked_content', {})
                                if isinstance(rt_linked, dict):
                                    reading_type_info = {
                                        'uom': rt_linked.get('uom', {}).get('_value') if isinstance(rt_linked.get('uom'), dict) else rt_linked.get('uom'),
                                        'kind': rt_linked.get('kind', {}).get('_value') if isinstance(rt_linked.get('kind'), dict) else rt_linked.get('kind'),
                                        'powerOfTenMultiplier': rt_linked.get('powerOfTenMultiplier', {}).get('_value') if isinstance(rt_linked.get('powerOfTenMultiplier'), dict) else rt_linked.get('powerOfTenMultiplier'),
                                        'accumulationBehaviour': rt_linked.get('accumulationBehaviour', {}).get('_value') if isinstance(rt_linked.get('accumulationBehaviour'), dict) else rt_linked.get('accumulationBehaviour'),
                                    }
                            
                            # Generate tags based on available data
                            tags = self._generate_tags_from_reading(description, final_url, reading_type_info, item)
                            
                            # Create endpoint entry
                            endpoint = {
                                description: {
                                    'url': final_url,
                                    'tags': tags
                                }
                            }
                            endpoints.append(endpoint)
                            logger.debug(f"Found endpoint: {description} at {final_url}")
        
        except Exception as e:
            logger.error(f"Error processing UPT tree: {e}", exc_info=True)
            raise
        
        logger.info(f"Discovered {len(endpoints)} endpoints from UPT tree")
        
        # Save to file if requested
        if save_file:
            # Convert swVer to file version format (e.g., "3.2.50" -> "3_2_50")
            file_version = str(self._swVer).replace('.', '_')
            config_path = _SCRIPT_DIR / 'configs' / f'endpoints_{file_version}.yaml'
            
            logger.info(f"Saving discovered endpoints to {config_path}")
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(endpoints, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            logger.info(f"Successfully saved {len(endpoints)} endpoints to {config_path}")
        
        return endpoints
    
    def _generate_tags_from_reading(self, description: str, url: str, reading_type_info: dict, reading_item: dict) -> dict:
        """
        Generate tag configuration for a reading based on its description and type info.
        
        Args:
            description: Description of the reading
            url: URL of the reading endpoint
            reading_type_info: Dictionary with reading type information (uom, kind, etc.)
            reading_item: The full reading item from the tree
            
        Returns:
            dict: Tag configuration
        """
        tags = {}
        
        # Determine device class and unit based on description and reading type
        device_class = 'sensor'
        unit = ''
        state_class = 'measurement'
        value_template = None
        
        desc_lower = description.lower()
        
        # Check for power factor readings (need special handling for multiplier)
        if 'power factor' in desc_lower:
            device_class = 'power_factor'
            unit = ''
            # Check if multiplier is -3 (divide by 1000)
            multiplier = reading_type_info.get('powerOfTenMultiplier', 0)
            if multiplier == -3:
                value_template = '{{ value | float / 1000 if value else None }}'
            else:
                value_template = '{{ value | float / 1000 }}'
        
        # Check for energy readings
        elif 'wh' in desc_lower or 'watt' in desc_lower or 'summation' in desc_lower or 'tou' in desc_lower:
            device_class = 'energy'
            unit = 'Wh'
            state_class = 'total'
        
        # Check for power/demand readings
        elif 'demand' in desc_lower or 'instantaneous' in desc_lower:
            device_class = 'power'
            unit = 'W'
            state_class = 'measurement'
        
        # Check for VAh (apparent energy)
        elif 'vah' in desc_lower:
            device_class = 'energy'
            unit = 'VAh'
            state_class = 'total'
        
        # Check for VARh (reactive energy)
        elif 'varh' in desc_lower:
            device_class = 'energy'
            unit = 'VARh'
            state_class = 'total'
        
        # Default value tag
        value_tag = {
            'entity_type': 'sensor',
            'device_class': device_class,
            'state_class': state_class
        }
        
        if unit:
            value_tag['unit_of_measurement'] = unit
        
        if value_template:
            value_tag['value_template'] = value_template
        
        # Add enabled_by_default: false for VAh, VARh, and Power Factor Phase entries
        # All other entries get enabled_by_default: true
        is_vah = 'vah' in desc_lower and 'varh' not in desc_lower  # VAh but not VARh
        is_varh = 'varh' in desc_lower
        is_power_factor_phase = 'power factor' in desc_lower and ('phase' in desc_lower or 'phasea' in desc_lower or 'phaseb' in desc_lower or 'phasec' in desc_lower)
        
        if is_vah or is_varh or is_power_factor_phase:
            value_tag['enabled_by_default'] = False
        else:
            value_tag['enabled_by_default'] = True
        
        tags['value'] = value_tag
        
        # Add timePeriod tags (always available)
        tags['timePeriod'] = self._generate_timeperiod_tags()
        
        # Add qualityFlags tag (always disabled by default)
        tags['qualityFlags'] = {
            'entity_type': 'sensor',
            'state_class': 'measurement',
            'enabled_by_default': False
        }
        
        # Add touTier if this is a TOU reading or uses ReadingSetListLink
        if 'tou' in desc_lower or '/rs/' in url:
            tags['touTier'] = {
                'entity_type': 'sensor'
            }
        
        return tags
    
    def _generate_timeperiod_tags(self) -> list:
        """
        Generate tag configuration for timePeriod fields.
        
        Returns:
            list: List of tag configurations for duration and start
        """
        return [
            {
                'duration': {
                    'entity_type': 'sensor',
                    'device_class': 'duration',
                    'value_template': '{{ value }}',
                    'unit_of_measurement': 's'
                }
            },
            {
                'start': {
                    'entity_type': 'sensor',
                    'device_class': 'timestamp',
                    'value_template': '{{ as_datetime( value ) }}'
                }
            }
        ]

    def get_hardware_details(self, hw_info_url: str, hw_names: list) -> dict:
        """
        Queries the meter hardware endpoint at the ip address passed
        to the class.

        Returns: dict, {<element name>: <meter response>}
        """
        query_url = f'{self.url}{hw_info_url}'
        logger.debug(f"Querying meter at: {query_url}")

        try:
            # query the hw specs endpoint, slow it down to avoid overwhelming the device
            sleep(16)
            x = self.requests_session.get(query_url, verify=False, timeout=4.0)
            logger.debug(f"Successfully received response from meter")
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL Error details:")
            logger.error(f"  Error: {e}")
            logger.error(f"  Cipher configured: {CIPHERS}")
            logger.error(f"  SSL module version: {ssl.OPENSSL_VERSION}")
            # Check if OP_LEGACY_SERVER_CONNECT is available
            if hasattr(ssl, 'OP_LEGACY_SERVER_CONNECT'):
                logger.error(f"  OP_LEGACY_SERVER_CONNECT: available")
            else:
                logger.error(f"  OP_LEGACY_SERVER_CONNECT: NOT AVAILABLE - this may be the issue!")
            raise

        # Parse the response xml looking for the passed in element names
        root = ET.fromstring(x.text)
        hw_info_dict = {}
        for name in hw_names:
            hw_info_dict[name] = root.find(f'.//{IEEE_PREFIX}{name}').text

        return hw_info_dict

    @staticmethod
    def pretty_print_upt_tree(tree, indent: int = 0, prefix: str = "") -> str:
        """
        Formats the UPT tree structure as a readable string with indentation.
        
        Args:
            tree: The dictionary tree structure from map_upt_tree
            indent: Current indentation level
            prefix: Prefix for the current line
            
        Returns: str, formatted string representation of the tree
        """
        lines = []
        indent_str = "  " * indent
        
        if isinstance(tree, dict):
            for key, value in tree.items():
                if key == '_attributes':
                    attrs_str = ', '.join(f"{k}={v}" for k, v in value.items())
                    lines.append(f"{indent_str}{prefix}[attributes: {attrs_str}]")
                elif key == '_value':
                    lines.append(f"{indent_str}{prefix}value: {value}")
                elif isinstance(value, dict):
                    lines.append(f"{indent_str}{prefix}{key}:")
                    lines.append(xcelMeter.pretty_print_upt_tree(value, indent + 1))
                elif isinstance(value, list):
                    lines.append(f"{indent_str}{prefix}{key}: [list with {len(value)} items]")
                    for i, item in enumerate(value):
                        lines.append(f"{indent_str}  [{i}]:")
                        lines.append(xcelMeter.pretty_print_upt_tree(item, indent + 2))
                else:
                    lines.append(f"{indent_str}{prefix}{key}: {value}")
        elif isinstance(tree, list):
            for i, item in enumerate(tree):
                lines.append(f"{indent_str}[{i}]:")
                lines.append(xcelMeter.pretty_print_upt_tree(item, indent + 1))
        else:
            lines.append(f"{indent_str}{prefix}{tree}")
        
        return "\n".join(lines)

    def map_upt_tree(self, upt_url: str = '/upt', pretty_print: bool = False, visited_urls: set = None) -> dict:
        """
        Safely traverses the /upt tree to discover what information is available.
        Recursively walks through the XML structure and follows href links to map
        the entire tree structure.

        Args:
            upt_url: The URL path to query (default: '/upt')
            pretty_print: If True, print the tree in a formatted way (default: False)
            visited_urls: Set of URLs already visited to prevent infinite loops (internal use)

        Returns: dict, nested structure representing the XML tree with element names and values
        """
        # Initialize visited URLs set on first call
        if visited_urls is None:
            visited_urls = set()
        
        # Prevent infinite loops by tracking visited URLs
        if upt_url in visited_urls:
            logger.debug(f"Skipping already visited URL: {upt_url}")
            return {"_visited": True, "_url": upt_url}
        
        visited_urls.add(upt_url)
        query_url = f'{self.url}{upt_url}'
        logger.debug(f"Querying UPT tree at: {query_url}")

        try:
            # query the upt endpoint

            x = self.requests_session.get(query_url, verify=False, timeout=4.0)
            logger.debug(f"Successfully received response from UPT endpoint")
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL Error details:")
            logger.error(f"  Error: {e}")
            logger.error(f"  Cipher configured: {CIPHERS}")
            logger.error(f"  SSL module version: {ssl.OPENSSL_VERSION}")
            # Check if OP_LEGACY_SERVER_CONNECT is available
            if hasattr(ssl, 'OP_LEGACY_SERVER_CONNECT'):
                logger.error(f"  OP_LEGACY_SERVER_CONNECT: available")
            else:
                logger.error(f"  OP_LEGACY_SERVER_CONNECT: NOT AVAILABLE - this may be the issue!")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error querying UPT endpoint: {e}")
            raise

        # Parse the response xml
        try:
            root = ET.fromstring(x.text)
        except ET.ParseError as e:
            logger.error(f"Failed to parse XML response: {e}")
            logger.error(f"Response text: {x.text[:500]}")  # Log first 500 chars
            raise

        def traverse_element(element, path=""):
            """
            Recursively traverse an XML element and build a nested dictionary structure.
            
            Args:
                element: XML element to traverse
                path: Current path in the tree (for logging)
            
            Returns: dict or value representing the element
            """
            result = {}
            current_path = f"{path}/{element.tag.replace(IEEE_PREFIX, '')}" if path else element.tag.replace(IEEE_PREFIX, '')
            
            # Get text content if present
            if element.text and element.text.strip():
                text_content = element.text.strip()
                # Try to determine if it's a number
                try:
                    if '.' in text_content:
                        result['_value'] = float(text_content)
                    else:
                        result['_value'] = int(text_content)
                except ValueError:
                    result['_value'] = text_content
            
            # Get attributes if present
            if element.attrib:
                result['_attributes'] = element.attrib
            
            # Recursively process children
            children = {}
            for child in element:
                child_tag = child.tag.replace(IEEE_PREFIX, '')
                child_path = f"{current_path}/{child_tag}"
                
                # If multiple children with same tag, make it a list
                if child_tag in children:
                    if not isinstance(children[child_tag], list):
                        children[child_tag] = [children[child_tag]]
                    children[child_tag].append(traverse_element(child, current_path))
                else:
                    children[child_tag] = traverse_element(child, current_path)
            
            # Merge children into result
            result.update(children)
            
            # If result only has _value, return just the value for cleaner output
            if len(result) == 1 and '_value' in result:
                return result['_value']
            # If result only has _value and _attributes, keep structure but simplify
            if len(result) == 2 and '_value' in result and '_attributes' in result:
                return result
            
            return result

        # Traverse the root element
        upt_tree = traverse_element(root)
        
        # Recursively find and follow href links
        def find_and_follow_hrefs(tree_node, parent_path=""):
            """
            Recursively find href fields and follow them.
            
            Args:
                tree_node: Current node in the tree (dict, list, or value)
                parent_path: Path to current node for logging
            """
            if isinstance(tree_node, dict):
                href_url = None
                all_count = None
                
                # Check for href in attributes
                if '_attributes' in tree_node and 'href' in tree_node['_attributes']:
                    href_url = tree_node['_attributes']['href']
                    # Check for 'all' attribute indicating total count
                    if 'all' in tree_node['_attributes']:
                        try:
                            all_count = int(tree_node['_attributes']['all'])
                        except (ValueError, TypeError):
                            pass
                
                # Check if there's a child element named 'href' with a value
                elif 'href' in tree_node:
                    href_value = tree_node['href']
                    if isinstance(href_value, str):
                        href_url = href_value
                    elif isinstance(href_value, dict) and '_value' in href_value:
                        href_url = href_value['_value']
                
                # Follow the href if found
                if href_url and isinstance(href_url, str) and href_url.startswith('/'):
                    logger.info(f"Found href at {parent_path}: {href_url}" + (f" (all={all_count})" if all_count else ""))
                    try:
                        # Recursively map the href URL
                        linked_tree = self.map_upt_tree(href_url, pretty_print=False, visited_urls=visited_urls)
                        
                        # If 'all' attribute indicates more items than we got, try to fetch all
                        if all_count is not None and all_count > 1:
                            # Check how many items we actually got
                            items_found = 0
                            list_key = None
                            
                            if isinstance(linked_tree, dict):
                                # Look for list items (common patterns)
                                for key, value in linked_tree.items():
                                    if isinstance(value, list):
                                        items_found = len(value)
                                        list_key = key
                                        break
                                    elif key not in ['_attributes', '_value', '_linked_content', '_href_error', '_href_url', '_visited', '_url']:
                                        # Might be a single item, check if there should be more
                                        # If it's a dict with href attributes, it might be a single item
                                        if isinstance(value, dict) and '_attributes' in value and 'href' in value.get('_attributes', {}):
                                            items_found = 1
                                            list_key = key
                            
                            if items_found < all_count:
                                logger.info(f"Found {items_found} items but 'all'={all_count}, attempting to fetch all items from {href_url}")
                                # Try to fetch all items by querying each one individually
                                all_items = []
                                base_url = href_url.rstrip('/')
                                
                                for i in range(1, all_count + 1):
                                    item_url = f"{base_url}/{i}"
                                    if item_url not in visited_urls:
                                        try:
                                            item_tree = self.map_upt_tree(item_url, pretty_print=False, visited_urls=visited_urls)
                                            all_items.append(item_tree)
                                            logger.debug(f"Fetched item {i}/{all_count} from {item_url}")
                                        except Exception as e:
                                            logger.warning(f"Failed to fetch item {i} from {item_url}: {e}")
                                            # Still add a placeholder
                                            all_items.append({"_error": str(e), "_url": item_url})
                                        
                                        # Add 1 second pause between queries to not overwhelm the device
                                        if i < all_count:  # Don't sleep after the last item
                                            sleep(1)
                                    else:
                                        logger.debug(f"Skipping already visited item {i} from {item_url}")
                                
                                # Replace the linked_tree with all items
                                if all_items:
                                    # Try to preserve the structure - if linked_tree has a list key, use that
                                    if isinstance(linked_tree, dict):
                                        if list_key:
                                            linked_tree[list_key] = all_items
                                        else:
                                            # Find the first non-metadata key or create a new one
                                            for key in linked_tree.keys():
                                                if key not in ['_attributes', '_value', '_visited', '_url']:
                                                    linked_tree[key] = all_items
                                                    break
                                            else:
                                                # No suitable key found, create a generic list
                                                linked_tree['_all_items'] = all_items
                                                linked_tree['_item_count'] = len(all_items)
                                    else:
                                        linked_tree = {'_all_items': all_items, '_item_count': len(all_items)}
                                
                                logger.info(f"Successfully fetched {len(all_items)}/{all_count} items")
                        
                        # Store the linked tree
                        tree_node['_linked_content'] = linked_tree
                    except Exception as e:
                        logger.warning(f"Failed to follow href {href_url}: {e}")
                        tree_node['_href_error'] = str(e)
                        tree_node['_href_url'] = href_url
                
                # Recursively process all children
                for key, value in tree_node.items():
                    if key not in ['_attributes', '_value', '_linked_content', '_href_error', '_href_url']:
                        find_and_follow_hrefs(value, f"{parent_path}/{key}" if parent_path else key)
                        
            elif isinstance(tree_node, list):
                for i, item in enumerate(tree_node):
                    find_and_follow_hrefs(item, f"{parent_path}[{i}]" if parent_path else f"[{i}]")
        
        # Find and follow all href links
        logger.info(f"Searching for href links in tree from {upt_url}")
        find_and_follow_hrefs(upt_tree, upt_url)
        
        logger.info(f"Successfully mapped UPT tree from {upt_url} (visited {len(visited_urls)} URLs)")
        
        # Pretty print if requested
        if pretty_print:
            print("\n" + "="*60)
            print(f"UPT Tree Structure: {upt_url}")
            print(f"Total URLs visited: {len(visited_urls)}")
            print("="*60)
            print(self.pretty_print_upt_tree(upt_tree))
            print("="*60 + "\n")
        
        return upt_tree

    @staticmethod
    def setup_session(creds: tuple, ip_address: str) -> requests.Session:
        """
        Creates a new requests session with the given credentials pointed
        at the give IP address. Will be shared across each xcelQuery object.

        Returns: request.session
        """
        session = requests.Session()
        session.cert = creds
        # Mount our adapter to the domain, passing the client cert/key
        # creds is a tuple of (cert_file, key_file)
        cert_file, key_file = creds
        session.mount(f'https://{ip_address}', CCM8Adapter(cert_file=cert_file, key_file=key_file))

        return session

    @staticmethod
    def load_endpoints(file_path: str) -> list:
        """
        Loads the yaml file passed containing meter endpoint information

        Returns: list
        """
        with open(file_path, mode='r', encoding='utf-8') as file:
            endpoints = yaml.safe_load(file)

        return endpoints

    def create_endpoints(self, endpoints: dict, device_info: dict) -> None:
        # Build query objects for each endpoint
        query_obj = []
        for point in endpoints:
            for endpoint_name, v in point.items():
                request_url = f'{self.url}{v["url"]}'
                query_obj.append(xcelEndpoint(self.requests_session, self.mqtt_client,
                                    request_url, endpoint_name, v['tags'], device_info))

        return query_obj

    @staticmethod
    def get_mqtt_port() -> int:
        """
        Identifies the port to use for the MQTT server. Very basic,
        just offers a detault of 1883 if no other port is set

        Returns: int
        """
        env_port = os.getenv('MQTT_PORT')
        # If environment variable for MQTT port is set, use that
        # if not, use the default
        mqtt_port = int(env_port) if env_port else 1883

        return mqtt_port

    @staticmethod
    def setup_mqtt(mqtt_server_address, mqtt_port) -> mqtt.Client:
        """
        Creates a new mqtt client to be used for the the xcelQuery
        objects.

        Returns: mqtt.Client object
        """
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                logging.info("Connected to MQTT Broker!")
            else:
                logging.error("Failed to connect, return code %d\n", rc)

        # Check if a username/PW is setup for the MQTT connection
        mqtt_username = os.getenv('MQTT_USER')
        mqtt_password = os.getenv('MQTT_PASSWORD')
        # If no env variable was set, skip setting creds?
        client = mqtt.Client()
        if mqtt_username and mqtt_password:
            client.username_pw_set(mqtt_username, mqtt_password)
        client.on_connect = on_connect
        logging.info(f"MQTT connection details:")
        logging.info(f"MQTT_ADDRESS: {mqtt_server_address}")
        logging.info(f"MQTT_PORT: {mqtt_port}")
        logging.info(f"MQTT_USER: {mqtt_username}")
        client.connect(mqtt_server_address, mqtt_port)
        client.loop_start()

        return client

    # Send MQTT config setup to Home assistant
    def send_configs(self):
        """
        Sends the MQTT config to the homeassistant topic for
        automatic discovery

        Returns: None
        """
        for obj in self.query_obj:
            obj.mqtt_send_config()
            input()

    def send_mqtt_config(self) -> None:
        """
        Sends a discovery payload to homeassistant for the new meter device

        Returns: None
        """
        mqtt_topic_prefix = os.getenv('MQTT_TOPIC_PREFIX', 'homeassistant')
        state_topic = f'{mqtt_topic_prefix}/device/energy/{self.name.replace(" ", "_").lower()}'
        config_dict = {
            "name": self.name,
            "device_class": "energy",
            "state_topic": state_topic,
            "unique_id": self._lfdi
            }
        config_dict.update(self.device_info)
        config_json = json.dumps(config_dict)
        logging.debug(f"Sending MQTT Discovery Payload")

        result = self.mqtt_client.publish(state_topic, str(config_json))
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            logging.debug(f"MQTT discovery payload published successfully (mid: {result.mid})")
            logging.debug(f"TOPIC: {state_topic}")
            logging.debug(f"Config: {config_json}")
        elif result.rc == mqtt.MQTT_ERR_NO_CONN:
            logging.error(f"MQTT publish failed: Not connected to broker")
        else:
            logging.error(f"MQTT publish failed with return code: {result.rc}")

    def run(self) -> None:
        """
        Main business loop. Just repeatedly queries the meter endpoints,
        parses the results, packages these up into MQTT payloads, and sends
        them off to the MQTT server

        Returns: None
        """

        while True:
            sleep(self.POLLING_RATE)
            for obj in self.endpoints:
                obj.run()
