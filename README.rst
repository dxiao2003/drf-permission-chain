.. coding=utf-8

Permission chains for Django Rest Framework
===========================================

Permission chains provide a structured framework for dealing with complex
permissions in Django and DRF applications.  A "permission chain" is a sequence
of objects linking an object involved in a CRUD request to the user making that
request.  By inspecting the chain, the application can determine whether or not
to authorize the operation.