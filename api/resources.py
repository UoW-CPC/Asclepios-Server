from tastypie.resources import ModelResource, Resource, fields
from api.models import CipherText, Map
from tastypie.authorization import Authorization
from tastypie.bundle import Bundle
from tastypie.exceptions import NotFound
import requests
import json
import hashlib
# import the logging library
import logging
import os

#===============================================================================
# Common functions
#===============================================================================  
def hash(input):
    h = hashlib.sha256(input).hexdigest()
    return h


# Get an instance of a logger
logger = logging.getLogger(__name__)

# Get URL of Trusted Authority (TA)
URL_TA = os.environ['TA_SERVER']#"http://127.0.0.1:8000/api/v1/search/"#"http://127.0.0.1:8000/api/v1/search/" #os.getenv('TA_SERVER')
    
#===============================================================================
# "Ciphertext" resource
#===============================================================================   
class CiphertextResource(ModelResource):

    class Meta:
        queryset = CipherText.objects.all()
        resource_name = 'ciphertext'
        authorization = Authorization()
        filtering = {
            "jsonId": ['exact'],
        }

    
#===============================================================================
# "Map" resource
#===============================================================================   
class MapResource(ModelResource):

    class Meta:
        queryset = Map.objects.all()
        resource_name = 'map'
        authorization = Authorization()
        filtering = {
            "address": ['exact'],
            "value": ['exact'],
        }

    
#===============================================================================
# "Search Query" object
#===============================================================================       
class Search(object):
    KeyW = ''
    fileno = 0
    Lu = []
    Cfw = []

    
#===============================================================================
# "Search Query" resource
#===============================================================================   
class SearchResource(Resource):
    KeyW = fields.CharField(attribute='KeyW')
    fileno = fields.IntegerField(attribute='fileno')
    Lu = fields.ListField(attribute='Lu')
    Cfw = fields.ListField(attribute="Cfw")
    
    class Meta:
        resource_name = 'search'
        object_class = Search
        authorization = Authorization()
        always_return_data=True

    # adapted this from ModelResource
    def get_resource_uri(self, bundle_or_obj):
        kwargs = {
            'resource_name': self._meta.resource_name,
        }

        if isinstance(bundle_or_obj, Bundle):
            kwargs['pk'] = bundle_or_obj.obj.KeyW  # pk is referenced in ModelResource
        else:
            kwargs['pk'] = bundle_or_obj.KeyW
        
        if self._meta.api_name is not None:
            kwargs['api_name'] = self._meta.api_name
        
        return self._build_reverse_url('api_dispatch_detail', kwargs=kwargs)

    def get_object_list(self, request):
        # inner get of object list... this is where you'll need to
        # fetch the data from what ever data source
        return 0

    def obj_get_list(self, request=None, **kwargs):
        # outer get of object list... this calls get_object_list and
        # could be a point at which additional filtering may be applied
        return self.get_object_list(request)

    def obj_get(self, request=None, **kwargs):
        # get one object from data source
        data = {"KeyW":self.KeyW, "fileno":self.fileno, "Lu":self.Lu, "Cfw":self.Cfw}
        return data
    
    def obj_create(self, bundle, request=None, **kwargs):
        logger.info("Search in SSE Server")
        logger.debug("TA url: %s",URL_TA)
        
        # create a new object
        bundle.obj = Search()
         
        # full_hydrate does the heavy lifting mapping the
        # POST-ed payload key/values to object attribute/values
        bundle = self.full_hydrate(bundle)
         
        logger.debug("Received data from user: - KeyW: %s, - file number: %s, - Lu: %s",bundle.obj.KeyW, bundle.obj.fileno, bundle.obj.Lu)
        
        # invoke API of TA
        fileno = bundle.obj.fileno
        KeyW = json.dumps(bundle.obj.KeyW)
        
        logger.debug("KeyW: %s", KeyW)
        
        data = {}
        data["KeyW"] = bundle.obj.KeyW
        data["fileno"] = bundle.obj.fileno
        
        logger.debug("json data: {}", data)
        logger.debug("URL_TA: %s",URL_TA)
        
        # Send request to TA
        logger.debug("Send request to TA")
        response = requests.post(URL_TA, json=data)  
        
        logger.debug("Response from TA: Lta = %s", response.text)
        
        # compare the list received from TA with the list received from the user
        Lu = bundle.obj.Lu
        logger.debug("List from user: %s", Lu)
        Lta = response.json()["Lta"]
        logger.debug("List from TA: %s", Lta)
        
        if Lu == Lta:
            logger.debug("Lu = Lta")
            
            # List of encrypted data
            CipherL = []

            logger.debug("fileno: %s",fileno) 
            KeyW_ciphertext = json.loads(KeyW)['ct'] # get value of json 
            for i in range(1, int(fileno) + 1): # fileno starts at 1
                logger.debug("i: %d", i)
                input =  (KeyW_ciphertext + str(i) + "0").encode('utf-8')
                addr = hash(input)
                logger.debug("hash input to compute address: %s", input)
                logger.debug("the hash output (computed from KeyW): %s", addr)
                logger.debug("type of addr: %s",type(addr))

                try:
                    logger.debug("finding address")
                    
                    # Retrieve value which corresponds to the address 'addr'
                    cf = Map.objects.get(address=addr).value
                    logger.debug("File identifier: %s",cf)
                    
                    # Retrieve ciphertexts
                    ct = CipherText.objects.filter(jsonId=cf).values()
                    logger.debug("Ciphertext of the same file: %s",ct)
                    CipherL.append(list(ct))
                    
                    # Delete the current (address, value) and update with the new (address, value)
                    Map.objects.get(address=addr).delete()
                    logger.debug("New address: %s",Lu[i-1])
                    Map.objects.create(address=Lu[i-1],value=cf) # fileno == length(Lu)
                except:
                    logger.debug("Not found: %s",addr)
                    cf = None
                        
            bundle.obj.Cfw = CipherL
            logger.debug("The list of ciphertext: %s",CipherL)

            bundle.obj.KeyW = '' # hide KeyW in the response
            bundle.obj.fileno = 0 # hide fileNo in the response  
            bundle.obj.Lu=[]     # hide Lu in the response  

            logger.debug("Send list of ciphertext (Cfw) back to the user: %s", bundle)
        else:
            logger.debug("Lu!=Lta")
        
 
        return bundle
    
#===============================================================================
# "Update Query" object
#===============================================================================       
class Update(object):
    LkeyW = [] # list of KeyW
    LfileNo = [] # list of No.Files
    Ltemp = [] # list of temp addresses
    Lnew = [] # list of new addresses
    status = 0 # status of update, i.e. 0 if not found, 1 if updated
    file_id=""
    Lcurrentcipher = []
    Lnewcipher = []
    
#===============================================================================
# "Update Query" resource
#===============================================================================   
class UpdateResource(Resource):
    LkeyW = fields.ListField(attribute='LkeyW')
    Lfileno = fields.ListField(attribute='Lfileno')
    Ltemp = fields.ListField(attribute='Ltemp')
    Lnew = fields.ListField(attribute='Lnew')
    status = fields.IntegerField(attribute='status')
    file_id = fields.CharField(attribute='file_id')
    Lcurrentcipher = fields.ListField(attribute='Lcurrentcipher')
    Lnewcipher = fields.ListField(attribute='Lnewcipher')
    
    class Meta:
        resource_name = 'update'
        object_class = Update
        authorization = Authorization()
        always_return_data=True

    # adapted this from ModelResource
    def get_resource_uri(self, bundle_or_obj):
        kwargs = {
            'resource_name': self._meta.resource_name,
        }

        if isinstance(bundle_or_obj, Bundle):
            kwargs['pk'] = bundle_or_obj.obj.LkeyW# pk is referenced in ModelResource
        else:
            kwargs['pk'] = bundle_or_obj.LkeyW
        
        if self._meta.api_name is not None:
            kwargs['api_name'] = self._meta.api_name
        
        return self._build_reverse_url('api_dispatch_detail', kwargs=kwargs)

    def get_object_list(self, request):
        # inner get of object list... this is where you'll need to
        # fetch the data from what ever data source
        return 0

    def obj_get_list(self, request=None, **kwargs):
        # outer get of object list... this calls get_object_list and
        # could be a point at which additional filtering may be applied
        return self.get_object_list(request)

    def obj_get(self, request=None, **kwargs):
        # get one object from data source
        data = {"file_id %s":self.file_id, "LkeyW {}":self.LkeyW, "Lfileno %s":self.Lfileno, "Ltemp %s":self.Ltemp, "Lnew %s":self.Lnew, "Lcurrentcipher %s":self.Lcurrentcipher,"Lnewcipher %s": self.Lnewcipher, "status %s":self.status}
        return data
    
    def obj_create(self, bundle, request=None, **kwargs):
        logger.info("Update in SSE Server")
        logger.debug("TA url: %s",URL_TA)
        
        # create a new object
        bundle.obj = Update()
         
        # full_hydrate does the heavy lifting mapping the
        # POST-ed payload key/values to object attribute/values
        bundle = self.full_hydrate(bundle)
           
        # invoke API of TA
        file_id = bundle.obj.file_id
        Lfileno = bundle.obj.Lfileno   
        LkeyW=bundle.obj.LkeyW
        Ltemp = bundle.obj.Ltemp
        Lnew = bundle.obj.Lnew
        Lcurrent_cipher = bundle.obj.Lcurrentcipher
        Lnew_cipher = bundle.obj.Lnewcipher
        
        logger.debug("Received data from user: - file_id: %s, - LkeyW: %s,- List file number: %s, - Ltemp: %s,- Lnew: %s",file_id,LkeyW,Lfileno,Ltemp,Lnew)
              
        length = len(bundle.obj.LkeyW)
        data = []
        for i in range(0,length):
            item = {}
            item["KeyW"] = bundle.obj.LkeyW[i]
            data.append(item)
        
       # logger.debug("List of objects:%s",data)
        object = {}
        object["objects"]=data
       
        # Send request to TA
        logger.debug("Object sent to TA: %s",json.dumps(object)) 
        response = requests.patch(URL_TA, json=object)  
      
        logger.debug("Response from TA: Lta = %s", response.text)
          
        # check if the list received from TA contains the list received from the user
        Lobject = response.json()["objects"]
        logger.debug("List from TA: %s", Lobject)
         
        flag = True
         
        for i in range(0,length):
            Lta = Lobject[i]["Lta"] # list of addresses computed by TA with No.Search + 1
            logger.debug("List %d from TA %s",i,Lta)
            Lu = Ltemp[i] # list of addresses computed for i_th keyword by user with No.Search+1
            logger.debug("List %d from user: %s",i,Lu)
            if not(Lu == Lta): # if found any non-match (exits a a keyword, of which addresses computed by user and TA are different)
                flag=False
                i = length # exit For loop
                logger.debug("not match")
         
        if flag==True:
            logger.debug("matched")
            logger.debug("Lfileno: %s",Lfileno)
                     
            for j in range(0,length): # loop over each field
                KeyW = LkeyW[j] 
                logger.debug("j: %d, KeyW: %s",j,KeyW)
                KeyW_ciphertext = KeyW['ct'] # get value of json
                fileno = Lfileno[j]

                # find the entry in Map table
                for i in range(1, int(fileno) + 1): # fileno starts at 1
                    logger.debug("i: %d", i)
                    input =  (KeyW_ciphertext + str(i) + "0").encode('utf-8')
                    addr = hash(input)
                    logger.debug("hash input to compute address: %s", input)
                    logger.debug("the hash output (computed from KeyW): %s", addr)
                    logger.debug("type of addr: %s",type(addr))
    
                    try:
                        logger.debug("finding address")
                        cf = Map.objects.filter(address=addr,value=file_id)
                        count = cf.count()
                        logger.debug("number of found items:%d",count)
                        if (count>0):
                            logger.debug("Found item at i=%d",i)
                            logger.debug("Found item is: %s",cf)
                            ret = i

                            logger.debug("ends at item:%d",i)
                            
                            # Delete the current (address, value) and update with the new (address, value)
                            logger.debug("Delete the entry")
                            cf.delete()
                            
                            # add new address
                            logger.debug("New address: %s", Lnew[j])
                            logger.debug("Add new address")
                            Map.objects.create(address=Lnew[j][0], value=file_id)
                            
                            logger.debug("fileno:%d",int(fileno))
                            
                            
                            if i < int(fileno): # replace address of the last entry of the same keyword
                                logger.debug("Replace the item with the lastly-added address of the same keyword")
                                lastitem_input =  (KeyW_ciphertext + str(fileno) + "0").encode('utf-8')
                                logger.debug("lastly-added item input:%s",KeyW_ciphertext + str(fileno) + "0")
                                lastitem_addr = hash(lastitem_input)
                                logger.debug("The address of lastly-added item of the same keyword:%s",lastitem_addr)
                                lastitem = Map.objects.get(address=lastitem_addr)
                                logger.debug("Lastly-added item of the same keyword:%s,%s",lastitem.address,lastitem.value)
                                lastitem_fileid = lastitem.value
                                logger.debug("File id of lastly-added item of the same keyword:%s",lastitem_fileid)
                                lastitem.delete()
                                Map.objects.create(address=addr, value=lastitem_fileid)
                            else:
                                logger.debug("i (%d) is larger than fileno (%d)",i,int(fileno))
                
                     
                            # find the ciphertext in Cipher table 
                            # Note that in this implementation, ciphertext of the same keywords in different files are the same
                            logger.debug("Replace ciphertext")
                            data = CipherText.objects.filter(data=Lcurrent_cipher[j], jsonId=file_id) 
                            logger.debug("current cipher: %s", data)
                            data.delete()
                            logger.debug("new cipher: {}", Lnew_cipher[j])
                            CipherText.objects.create(data=Lnew_cipher[j], jsonId=file_id)
                        
                            i=int(fileno)+1 # stop the for loop
                    except:
                        logger.debug("Not found: %s",addr)
                        cf = None                         
        return bundle

