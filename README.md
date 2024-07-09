# Iam python SDK

IAM is a proprietary package made by VisaPick group to enterprice purposes.

## Installation

- Just run ` pip install git+https://github.com/Visapick-Team/IAM-SDK@main`

## FastAPI Example
### Dependency
```python
from iam.validation import Authorize
from iam.schema import TokenPayload

@router.get('/admin/{uuid}')
def function(
        uuid: str,
        user: TokenPayload = Depends(Authorize(
            roles=['admin'], scopes=["product:object:get"]))
    ):
    ...
```

## Django Example

### ModelViewSet or GenericViewSet

```python
from rest_framework.viewsets import ModelViewSet
from iam.permissions import AutoScopePermission


class SampleScopePermission(AutoScopePermission):
    _service_name = "service"

class MyModelViewSet(ModelViewSet):
    permission_classes = [SampleScopePermission]
    queryset = MyModel.objects.all()
    serializer_class = MyModelSerializer
    object_name = "sample"
```
This will validate below scopes for all actions in the MyModelViewSet.
```
service:sample:get
service:sample:list
service:sample:create
service:sample:update
service:sample:delete
```
if you are using custom actions, the permission class can handle your action and will check like this
```
service:sample:custom_action
```



### Function-Base APIView

```python
from rest_framework.decorators import api_view
from iam.permissions import scope_permission


@api_view(['DELETE'])
@scope_permission(":profile:delete")
def SampleFunctionAPIView(request):
    return Response({"message": "Herkese selam"})
```

# Contributors

<p align="left"> <img style="border-radius:5px" src="https://avatars.githubusercontent.com/u/52266113?v=4" width="32">

[Mohammadreza](https://github.com/zolghadri) (Maintainer)

</p>

