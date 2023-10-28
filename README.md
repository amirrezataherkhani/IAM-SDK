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

### ModelViewSet

```python
from rest_framework.viewsets import ModelViewSet
from rest_framework import permissions

class IsUser(permissions.BasePermission):

    def has_permission(self, request, view):

        user = get_user_from_token(request=request)
        authorize = Authorize(roles=roles)
        authorize(user=user)

        return True


class MyModelViewSet(ModelViewSet):
    permission_classes = [IsUser]
    queryset = MyModel.objects.all()
    serializer_class = MyModelSerializer
```

# Contributors

<p align="left"> <img style="border-radius:5px" src="https://avatars.githubusercontent.com/u/52266113?v=4" width="32">

[Mohammadreza](https://github.com/zolghadri) (Maintainer)

</p>
