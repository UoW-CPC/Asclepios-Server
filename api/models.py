from django.db import models

# Create your models here.

class CipherText(models.Model):
	jsonId = models.CharField(max_length=300)
	#data = models.CharField(max_length=300)
	data = models.TextField()
	def __str__(self):
		return '%s %s' % (self.jsonId, self.data)

class Map(models.Model):
	address = models.CharField(max_length=300)
	value = models.CharField(max_length=300) # file identifiers
	def __str__(self):
		return '%s %s' % (self.address, self.value) 	
