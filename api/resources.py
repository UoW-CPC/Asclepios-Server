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

from datetime import timedelta
from minio import Minio
#from minio.error import ResponseError

#===============================================================================
# Common functions
#===============================================================================  
def hash(input):
    h = hashlib.sha256(input).hexdigest()
    return h


# Get an instance of a logger
logger = logging.getLogger(__name__)

# Get URL of Trusted Authority (TA)
URL_TA = os.environ['TA_SERVER']+"/api/v1/search/"#"http://127.0.0.1:8000/api/v1/search/"#"http://127.0.0.1:8000/api/v1/search/" #os.getenv('TA_SERVER')
MINIO_ACCESS_KEY=os.environ['MINIO_ACCESS_KEY']
MINIO_SECRET_KEY=os.environ['MINIO_SECRET_KEY']
MINIO_BUCKET_NAME= os.environ['MINIO_BUCKET_NAME']
MINIO_URL = os.environ['MINIO_URL']
MINIO_SSL_SECURE=os.environ['MINIO_SSL_SECURE']
MINIO_EXPIRE_GET=os.environ['MINIO_EXPIRE_GET'] # number of days before expired (for GET presign url)
MINIO_EXPIRE_PUT=os.environ['MINIO_EXPIRE_PUT'] # number of days before expired (for PUT presign url)
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
            "keyId": ['exact'],
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
            "keyId": ['exact'],
        }

    
#===============================================================================
# "Search Query" object
#===============================================================================       
class Search(object):
    KeyW = ''
    fileno = 0
    Lu = []
    Cfw = []
    keyId = ''
    isfe = False
    
#===============================================================================
# "Search Query" resource
#===============================================================================   
class SearchResource(Resource):
    KeyW = fields.CharField(attribute='KeyW')
    fileno = fields.IntegerField(attribute='fileno')
    Lu = fields.ListField(attribute='Lu')
    Cfw = fields.ListField(attribute="Cfw")
    keyId = fields.CharField(attribute="keyId")
    isfe = fields.BooleanField(attribute="isfe") # true if requesting only json id (file id) and key id (which is then used for functional encryption (FE), false if requesting data content

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
        data = {"KeyW":self.KeyW, "fileno":self.fileno, "Lu":self.Lu, "Cfw":self.Cfw, "isfe":self.isfe}
        return data
    
    def obj_create(self, bundle, request=None, **kwargs):
        logger.info("Search in SSE Server")
        logger.debug("TA url: %s",URL_TA)
        
        # create a new object
        bundle.obj = Search()
         
        # full_hydrate does the heavy lifting mapping the
        # POST-ed payload key/values to object attribute/values
        bundle = self.full_hydrate(bundle)
         
        logger.debug("Received data from user: - KeyW: {}, - file number: {}, - Lu: {}, id of key: {}, isfe: {}".format(bundle.obj.KeyW, bundle.obj.fileno, bundle.obj.Lu, bundle.obj.keyId, bundle.obj.isfe))

        # invoke API of TA
        fileno = bundle.obj.fileno
        KeyW = json.dumps(bundle.obj.KeyW)
        keyid=bundle.obj.keyId
        
        data = {}
        data["KeyW"] = bundle.obj.KeyW
        data["keyId"] = bundle.obj.keyId
        
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
                    logger.debug("finding matched address")
                    
                    # Retrieve value which corresponds to the address 'addr'
                    cf = Map.objects.get(address=addr,keyId=keyid).value
                    logger.debug("File identifier: %s",cf)
        
                    if(bundle.obj.isfe==False):
                        # Retrieve ciphertexts
                        ct = CipherText.objects.filter(jsonId=cf,keyId=keyid).values()
                        logger.debug("Ciphertext of the same file: %s",ct)
                        CipherL.append(list(ct))
                    else: # return jsonId, and do not return data content
                        CipherL.append(cf)
                    
                    # Delete the current (address, value) and update with the new (address, value)
                    Map.objects.get(address=addr,keyId=keyid).delete()
                    logger.debug("New address: %s",Lu[i-1])
                    Map.objects.create(address=Lu[i-1],value=cf,keyId=keyid) # fileno == length(Lu)
                except:
                    logger.debug("Not found: %s",addr)
                    cf = None
                        
            bundle.obj.Cfw = CipherL
            logger.debug("The list of ciphertext: %s",CipherL)

            bundle.obj.KeyW = "" # hide KeyW in the response
            bundle.obj.fileno = 0 # hide fileNo in the response  
            bundle.obj.Lu=[]     # hide Lu in the response 
            bundle.obj.keyId="" 

            logger.debug("Send list of ciphertext (Cfw) back to the user: %s", bundle)
        else:
            logger.debug("Lu!=Lta")
            bundle.obj.KeyW = response.json()["KeyW"]
            logger.debug("Error message:%s",bundle.obj.KeyW)
 
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
    keyId =""
    
#===============================================================================
# "Update Query" resource
#===============================================================================   
class UpdateResource(Resource):
    LkeyW = fields.ListField(attribute='LkeyW')
    Lfileno = fields.ListField(attribute='Lfileno')
    Ltemp = fields.ListField(attribute='Ltemp')
    Lnew = fields.ListField(attribute='Lnew')
    status = fields.IntegerField(attribute='status')  # status of update, i.e. 0 if not found, 1 if deleted
    file_id = fields.CharField(attribute='file_id')
    Lcurrentcipher = fields.ListField(attribute='Lcurrentcipher')
    Lnewcipher = fields.ListField(attribute='Lnewcipher')
    keyId = fields.CharField(attribute='keyId')
    
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
        keyid = bundle.obj.keyId
        
        logger.debug("Received data from user: - file_id: %s, - LkeyW: %s,- List file number: %s, - Ltemp: %s,- Lnew: %s, - keyId: %s",file_id,LkeyW,Lfileno,Ltemp,Lnew,keyid)
              
        length = len(bundle.obj.LkeyW)
        data = []
        for i in range(0,length):
            item = {}
            item["KeyW"] = bundle.obj.LkeyW[i]
            item["keyId"] = keyid
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
                logger.debug("Replace ciphertext over different fields")
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
                        cf = Map.objects.filter(address=addr,value=file_id,keyId=keyid)
                        count = cf.count()
                        logger.debug("number of found items:%d",count)
                        if (count>0):
                            logger.debug("Found item at i=%d",i)
                            logger.debug("Found item is: {}    ",cf)
                            ret = i

                            logger.debug("ends at item:%d",i)
                            
                            # Delete the current (address, value) and update with the new (address, value)
                            logger.debug("Delete the entry")
                            cf.delete()
                            
                            # add new address
                            logger.debug("New address: %s", Lnew[j])
                            logger.debug("Add new address")
                            Map.objects.create(address=Lnew[j][0], value=file_id, keyId=keyid)
                            
                            logger.debug("fileno:%d",int(fileno))
                            
                            
                            if i < int(fileno): # replace address of the last entry of the same keyword
                                logger.debug("Replace the item with the lastly-added address of the same keyword")
                                lastitem_input =  (KeyW_ciphertext + str(fileno) + "0").encode('utf-8')
                                logger.debug("lastly-added item input:%s",KeyW_ciphertext + str(fileno) + "0")
                                lastitem_addr = hash(lastitem_input)
                                logger.debug("The address of lastly-added item of the same keyword:%s",lastitem_addr)
                                lastitem = Map.objects.get(address=lastitem_addr,keyId=keyid)
                                logger.debug("Lastly-added item of the same keyword:%s,%s",lastitem.address,lastitem.value)
                                lastitem_fileid = lastitem.value
                                logger.debug("File id of lastly-added item of the same keyword:%s",lastitem_fileid)
                                lastitem.delete()
                                Map.objects.create(address=addr, value=lastitem_fileid, keyId=keyid)
                            else:
                                logger.debug("i (%d) is equal fileno (%d)",i,int(fileno))
                
                     
                            # find the ciphertext in Cipher table 
                            # Note that in this implementation, ciphertext of the same keywords in different files are the same
                            logger.debug("Replace ciphertext")
                            data = CipherText.objects.filter(data=Lcurrent_cipher[j], jsonId=file_id, keyId = keyid) 
                            logger.debug("current cipher: {}", data)
                            data.delete()
                            logger.debug("new cipher: {}", Lnew_cipher[j])
                            CipherText.objects.create(data=Lnew_cipher[j], jsonId=file_id, keyId = keyid)
                        
                            i=int(fileno)+1 # stop the for loop
                    except:
                        logger.debug("Not found: %s",addr)
                        cf = None                         
        return bundle

#===============================================================================       
class Delete(object):
    LkeyW = [] # list of KeyW
    LfileNo = [] # list of No.Files
    Ltemp = [] # list of temp addresses
    Lnew = [] # list of new addresses
    status = 0 # status of update, i.e. 0 if not found, 1 if deleted
    file_id=""
    Lcurrentcipher = []
    Lnewcipher = []
    keyId = ""
    

#===============================================================================
# "Delete Query" resource
#===============================================================================   
class DeleteResource(Resource):
    LkeyW = fields.ListField(attribute='LkeyW')
    Lfileno = fields.ListField(attribute='Lfileno')
    Ltemp = fields.ListField(attribute='Ltemp')
    status = fields.IntegerField(attribute='status')
    file_id = fields.CharField(attribute='file_id')
    Lcipher = fields.ListField(attribute='Lcipher')
    keyId = fields.CharField(attribute='keyId')
    
    class Meta:
        resource_name = 'delete'
        object_class = Delete
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
        data = {"file_id %s":self.file_id, "LkeyW {}":self.LkeyW, "Lfileno %s":self.Lfileno, "Ltemp %s":self.Ltemp, "Lcipher %s":self.Lcipher,"status %s":self.status}
        return data
    
    def obj_create(self, bundle, request=None, **kwargs):
        logger.info("Delete in SSE Server")
        logger.debug("TA url: %s",URL_TA)
        
        # create a new object
        bundle.obj = Delete()
         
        # full_hydrate does the heavy lifting mapping the
        # POST-ed payload key/values to object attribute/values
        bundle = self.full_hydrate(bundle)
           
        # invoke API of TA
        file_id = bundle.obj.file_id
        Lfileno = bundle.obj.Lfileno   
        LkeyW=bundle.obj.LkeyW
        Ltemp = bundle.obj.Ltemp
        Lcipher = bundle.obj.Lcipher
        keyid = bundle.obj.keyId
        
        logger.debug("Received data from user for delete function: - file_id: %s, - LkeyW: %s,- List file number: %s, -Ltemp: %s, - Lcipher: %s",file_id,LkeyW,Lfileno,Ltemp,Lcipher)
              
        length = len(bundle.obj.LkeyW)
        data = []
        for i in range(0,length):
            item = {}
            item["KeyW"] = bundle.obj.LkeyW[i]
            item["keyId"] = keyid
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
                        cf = Map.objects.filter(address=addr,value=file_id, keyId = keyid)
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
                             
                            logger.debug("fileno:%d",int(fileno))
                            
                            
                            if i < int(fileno): # replace address of the last entry of the same keyword
                                logger.debug("Replace the item with the lastly-added address of the same keyword")
                                lastitem_input =  (KeyW_ciphertext + str(fileno) + "0").encode('utf-8')
                                logger.debug("lastly-added item input:%s",KeyW_ciphertext + str(fileno) + "0")
                                lastitem_addr = hash(lastitem_input)
                                logger.debug("The address of lastly-added item of the same keyword:%s",lastitem_addr)
                                lastitem = Map.objects.get(address=lastitem_addr, keyId=keyid)
                                logger.debug("Lastly-added item of the same keyword:%s,%s",lastitem.address,lastitem.value)
                                lastitem_fileid = lastitem.value
                                logger.debug("File id of lastly-added item of the same keyword:%s",lastitem_fileid)
                                lastitem.delete()
                                Map.objects.create(address=addr, value=lastitem_fileid, keyId=keyid)
                            else:
                                logger.debug("i (%d) is equal fileno (%d)",i,int(fileno))
                
                     
                            # find the ciphertext in Cipher table 
                            # Note that in this implementation, ciphertext of the same keywords in different files are the same
                            logger.debug("Delete ciphertext")
                            data = CipherText.objects.filter(data=Lcipher[j], jsonId=file_id, keyId = keyid) 
                            logger.debug("current cipher: %s", data)
                            data.delete()
                        
                            i=int(fileno)+1 # stop the for loop
                    except:
                        logger.debug("Not found: %s",addr)
                        cf = None                         
        return bundle

class PresignUrl(object):
    fname = ""
    url = ""
    
class PresignUrlResource(Resource):
    fname = fields.CharField(attribute='fname')
    url = fields.CharField(attribute='url')
    
    class Meta:
        resource_name = 'presign'
        object_class = PresignUrl
        authorization = Authorization()
        always_return_data=True
        fields = ['fname','url']

    def get_resource_uri(self, bundle_or_obj):
        kwargs = {
            'resource_name': self._meta.resource_name,
        }

        if isinstance(bundle_or_obj, Bundle):
            kwargs['pk'] = bundle_or_obj.obj.fname # pk is referenced in ModelResource
        else:
            kwargs['pk'] = bundle_or_obj.fname
          
        if self._meta.api_name is not None:
            kwargs['api_name'] = self._meta.api_name
          
        return self._build_reverse_url('api_dispatch_detail', kwargs = kwargs)
 
    def get_object_list(self, request):
        # inner get of object list... this is where you'll need to
        # fetch the data from what ever data source
        return 0
 
    def obj_get_list(self, request = None, **kwargs):
        # outer get of object list... this calls get_object_list and
        # could be a point at which additional filtering may be applied
        return self.get_object_list(request)
    def obj_get(self, bundle, request = None, **kwargs):
#         get one object from data source
        fname = kwargs['pk']         
        logger.debug("filename:%s",fname)
        
        minioClient = Minio(MINIO_URL,access_key=MINIO_ACCESS_KEY,secret_key=MINIO_SECRET_KEY,secure=json.loads(MINIO_SSL_SECURE.lower()))

        # presigned get object URL for object name, expires in 2 days.
        try:
            bundle_obj = PresignUrl()
            url=minioClient.presigned_get_object(MINIO_BUCKET_NAME, fname, expires=timedelta(days=int(MINIO_EXPIRE_GET)))
            logger.debug("url:%s",url)
            bundle_obj.url = url;
            bundle_obj.fname = fname;
            return bundle_obj;
        except KeyError:
            raise NotFound("Object not found")
        
    def obj_create(self, bundle, request=None, **kwargs):
        logger.info("Retrieve presign url for upload file to Minio")
        # full_hydrate does the heavy lifting mapping the
        # POST-ed payload key/values to object attribute/values
        bundle = self.full_hydrate(bundle)

        fname = bundle.obj.fname
        
        logger.debug("filename:%s",fname)

        minioClient = Minio(MINIO_URL,access_key=MINIO_ACCESS_KEY,secret_key=MINIO_SECRET_KEY,secure=json.loads(MINIO_SSL_SECURE.lower()))

        # presigned get object URL for object name, expires in 2 days.
        try:
            url=minioClient.presigned_put_object(MINIO_BUCKET_NAME, fname, expires=timedelta(days=int(MINIO_EXPIRE_PUT)))
            bundle.obj.url = url;
            bundle.obj.fname = fname;
        except KeyError:
            raise NotFound("Object not found")

        return bundle
