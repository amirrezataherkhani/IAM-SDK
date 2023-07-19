IAM is a proprietary package made by VisaPick group to enterprice purposes.

## Installation
+ Just run ``` pip install git+https://github.com/Visapick-Team/IAM-SDK@beta0```

## Token Validation

You better put this verification in a middleware.
```python
from iam.validation import JWTVerify

public_key_address = "<.pub FILE PATH>"
audience = '<AUDIENCE>'
jwtv = JWTVerify(public_key_address, audience)

token = "USER TOKEN WITHOUT BEARER AND WHITHSPACE"
if jwtv.verify(token):
    pass
else:
    raise Exception("The token is expired or invalid")
```


## Token Authorizing using scopes

If your are fastapi you should use this example.
```python

from fastapi import APIRouter
from typing import Annotated
from iam.schema import TokenPayload, Security
from iam.validation import get_user
from fastapi import  FastAPI


router = APIRouter()

@router.put('/profile/update')
async def update_user_profile(
        user: Annotated[TokenPayload,Security(get_user, scopes=["profile:update"], roles = ['user'])]
):
    // do something 

    pass

```
