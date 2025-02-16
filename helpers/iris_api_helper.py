from datetime import datetime
import os
import logging
from typing import Optional, List, Dict, Union

from dfir_iris_client.case import Case
from dfir_iris_client.session import ClientSession
from dfir_iris_client.helper.utils import parse_api_data, get_data_from_resp, assert_api_resp


# Set up logging configuration
LOG_FORMAT = '%(asctime)s %(levelname)s %(funcName)s: %(message)s'
logging.basicConfig(format=LOG_FORMAT, level='INFO', datefmt='%Y-%m-%d %I:%M:%S')
log = logging.getLogger(__name__)

#-------------------------------------- Functions --------------------------------------

# Overview of what functions are still TODO:
# [] Create new case (can basically use case.add_case)
# [] Upload key alerts (original notifications that triggered the investigation)
# [] Add events to a case (can use case.add_event) - More detailed than alerts, establish the timeline
# [] Create events from data extracted from the logs
# [] Create IOC (Indicator of Compromise) from data extracted from the logs (can use case.add_ioc)
#  -> Domains, Filenames, IPs + Ports, malware hashes, backdoor-scripts used, directories, more internal IPs etc.
# [] Create assets from data extracted from the logs (can use case.add_asset)
#  -> [] Compromised user accounts
#  -> [] Compromised computers / servers

# [] Possible: Add Evidence (actual data) e.g. Network packet captures, Log files, Disk Images, Memory dumps 


#-------------------------------------- IrisClient Class --------------------------------------
"""
A wrapper class for IRIS API interactions that provides high-level functions
for case management and related operations.
"""
class IrisClient:

    def __init__(self, api_key: str, host : str = "https://localhost/", ssl_verify: bool = False):
        """Initialize the IRIS client with connection details."""
        self.session = ClientSession(apikey=api_key, host=host, ssl_verify=ssl_verify)
        self.case = Case(session=self.session)

    """
    Check if a case with the given ID exists.
    Returns True if the case exists, False otherwise.
    """        
    def check_case_exists(self, case_id: int) -> bool:

        try:
            return self.case.case_id_exists(case_id)
        except Exception as e:
            log.error(f"Error checking case existence: {e}")
            return False
        
    """
    Create a new case with the given parameters.
    Returns the case ID if successful, None otherwise.
    """           
    def create_case(self, name: str,
                    description: str, 
                    customer: str = "DefaultCustomer", 
                    classification: str = "other:other",
                    soc_id: str = "soc_1") -> Optional[int]:
        try:
            status = self.case.add_case(
                case_name=name,
                case_description=description,
                case_customer=customer,
                case_classification=classification,
                soc_id=soc_id,
                create_customer=True
            )
            assert_api_resp(status, soft_fail=False)
            case_data = get_data_from_resp(status)
            return parse_api_data(case_data, 'case_id')
        except Exception as e:
            log.error(f"Error creating case: {e}")
            return None
            
    """
    Add an IOC to the specified case.
    Returns the IOC ID if successful, None otherwise.
    """
    def add_ioc_to_case(self, case_id: int,
                        value: str, 
                        ioc_type: str,
                        description: str = "",
                        ) -> Optional[int]:

        try:
            self.case.set_cid(case_id)
            status = self.case.add_ioc(value=value, ioc_type=ioc_type, description=description)
            assert_api_resp(status, soft_fail=False)
            ioc_data = get_data_from_resp(status)
            return parse_api_data(ioc_data, 'ioc_id')
        except Exception as e:
            log.error(f"Error adding IOC: {e}")
            return None
        
    """
    Add an asset to the specified case. 
    Returns the asset ID if successful, None otherwise.
    """           
    def add_asset_to_case(self, case_id: int,
                         name: str, 
                         asset_type: str, 
                         description: str,
                         compromise_status: int = 1,
                         domain: str = "",
                         ip: str = "",
                         additional_info: str = "",
                         analysis_status: str = "Started",
                         tags: List[str] = [],
                         ioc_links : List[int] = []) -> Optional[int]:

        try:
            self.case.set_cid(case_id)
            status = self.case.add_asset(
                name=name,
                asset_type=asset_type,
                description=description,
                compromise_status=compromise_status,
                domain=domain,
                ip=ip,
                additional_info=additional_info,
                analysis_status=analysis_status,
                tags=tags,
                ioc_links=ioc_links
            )
            assert_api_resp(status, soft_fail=False)
            asset_data = get_data_from_resp(status)
            return parse_api_data(asset_data, 'asset_id')
        except Exception as e:
            log.error(f"Error adding asset: {e}")
            return None
        
    """
    Add an event to the specified case.
    Returns the event ID if successful, None otherwise.
    """       
    def add_event_to_case(self, case_id: int,
                          title: str,
                          date_time: datetime,
                          content: str,
                          raw_content: str = "",
                          source: str = "",
                          linked_assets: List[int] = [],
                          linked_iocs: List[int] = [],
                          #category: str = "!!!!", #TODO
                          tags: List[str] = [],
                          display_in_graph: bool = True,
                          display_in_summary: bool = True,
                          ) -> Optional[int]:

        try:
            self.case.set_cid(case_id)
            status = self.case.add_event(
                title=title,
                date_time=date_time,
                content=content,
                raw_content=raw_content,
                source=source,
                linked_assets=linked_assets,
                linked_iocs=linked_iocs,
                #category=category, #TODO
                tags=tags,
                display_in_graph=display_in_graph,
                display_in_summary=display_in_summary
            )
            assert_api_resp(status, soft_fail=False)
            asset_data = get_data_from_resp(status)
            return parse_api_data(asset_data, 'event_id')
        except Exception as e:
            log.error(f"Error adding event: {e}")
            return None
        

    """
    Get the ID of a given IOC 
    Returns the IOC with the given value, if type is passed also matches the type.
    Returns the ID of the IOC if it exists, None otherwise.
    """   
    def check_ioc_exists(self, case_id: int, ioc_value: str, ioc_type: str = None) -> Optional[int]:
        try:
            self.case.set_cid(case_id)
            status = self.case.list_iocs()
            assert_api_resp(status, soft_fail=False)
            assert_data = get_data_from_resp(status)
            iocs = parse_api_data(assert_data, 'ioc')

            for ioc in iocs:
                if ioc['ioc_value'] == ioc_value and (ioc_type is None or ioc['ioc_type'] == ioc_type ):
                    return ioc['ioc_id']

            # NO matching IOC found
            return None
        
        except Exception as e:
            log.error(f"Error checking IOC existence: {e}")
            return None

#-------------------------------------- Example Code --------------------------------------

# This is an example of how to use the IRIS API to create a new case, add an IOC, add an asset, add notes directories and notes, taken from their documentation
def run_full_api_example():
    LOG_FORMAT = '%(asctime)s %(levelname)s %(funcName)s: %(message)s'

    logging.basicConfig(format=LOG_FORMAT, level='INFO', datefmt='%Y-%m-%d %I:%M:%S')
    log = logging.getLogger(__name__)

    # Initiate a session with our API key and host. Session stays the same during all the script run.
    session = ClientSession(apikey=os.environ.get('IRIS_API_KEY'),
                            host='https://localhost/', ssl_verify=False)

    # Initialize the case instance with the session
    case = Case(session=session)

    # Create a new case. The create_customer creates the customer if it doesn't exist, otherwise the method
    # would turn an error. This implies the calling user has administrative role.
    status = case.add_case(case_name='A new case created from script',
                        case_description='Short initial description, or really long '
                                            'description. It\'s up to you',
                        case_customer='IrisClientApiDemo',
                        case_classification='other:other',
                        soc_id='soc_1',
                        create_customer=True)

    # Always check the status as most of the methods do not raise exceptions. Setting soft_fail = False tells the client
    # to raise an exception if the request fails
    assert_api_resp(status, soft_fail=False)

    # All the methods are simply overlays of the API itself, so to know exactly what a method answers, one can either try
    # it or head to the API reference documentation and lookup the corresponding endpoint.
    # The case ID is returned by the server in case of success. We need this case ID for the next steps
    # Status are ApiResponse objects, and contains answers from the server.
    # While the ID could be retrieved with status.get_data().get('case_id'), it is preferable to use
    # the overlays get_data_from_resp and parse_api_data to be future proof, in case response from server are changed.
    case_data = get_data_from_resp(status)
    case_id = parse_api_data(case_data, 'case_id')

    log.info(f'Created case ID {case_id}')

    # Set the case instance with the new case ID. From now on, every action done with a method of the case instance
    # will be done under this case ID, except if the CID is explicitly provided on the method itself.
    # This can be used to directly modify existing cases etc.
    case.set_cid(case_id)


    # Let's add an IOC to our case
    # As in the GUI, not all attributes are mandatory. For instance here we have omitted everything not mandatory
    # Most of the methods auto resolve the types names. Here we set an IOC as AS directly, without specifying which ID is
    # the IOC AS type
    status_ioc = case.add_ioc(value='API IOC AS', ioc_type='AS')

    # We keep the ioc ID so we can add it to an asset later
    ioc_data = get_data_from_resp(status_ioc)
    ioc_id = parse_api_data(ioc_data, 'ioc_id')

    log.info(f'Created IOC ID {ioc_id}. Server returned {status_ioc}')

    # Let's add an asset and associate the ioc with an update
    status_asset = case.add_asset(name='API asset', asset_type='Windows - Computer',
                                description='A comprehensive description', compromise_status=1,
                                analysis_status='Started')
    assert_api_resp(status_asset, soft_fail=False)

    # We keep the asset ID so we can update it
    asset_data = get_data_from_resp(status_asset)
    asset_id = parse_api_data(asset_data, 'asset_id')

    log.info(f'Created asset ID {asset_id}')

    # Update the asset with the new ioc. By letting all fields empty except ioc_links, we only update this field.
    status_asset = case.update_asset(asset_id=asset_id, ioc_links=[ioc_id])
    assert_api_resp(status, soft_fail=False)

    log.info(f'Asset updated. Data :  {status_asset.as_json()}')

    # Add some notes directories
    status_dir1 = case.add_notes_directory('API Directory 1')
    assert_api_resp(status_dir1, soft_fail=False)

    log.info(f'Created API directory 1 notes directory')


    status_dir2 = case.add_notes_directory('API Directory 2')
    assert_api_resp(status_dir2, soft_fail=False)

    log.info(f'Created API directory 2 notes directory')


    status_dir3 = case.add_notes_directory('API Directory 3')
    assert_api_resp(status_dir3, soft_fail=False)

    log.info(f'Created API directory 3 notes group')

    # Get the group_id of Group 2 and add some notes
    dir_2_data = get_data_from_resp(status_dir2)
    dir_2_id = parse_api_data(data=dir_2_data, path='id')

    status_note = case.add_note(note_title='API note 1 for directory 2',
                                note_content='Anything you want really',
                                directory_id=dir_2_id)
    assert_api_resp(status_note, soft_fail=False)
    log.info(f'Created note API note 1 for group 2')


    status_note = case.add_note(note_title='API note 2 for directory 2',
                                note_content='Anything you want really',
                                directory_id=dir_2_id)
    assert_api_resp(status_note, soft_fail=False)
    log.info(f'Created note API note 2 for group 2')
