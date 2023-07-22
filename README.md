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


## Token Authorizing

If your are fastapi you should use this example.
```python

from fastapi import APIRouter
from iam.schema import TokenPayload
from iam.validation import Authorize


router = APIRouter()

@router.put('/profile/update')
async def update_user_profile(
        user: TokenPayload = Depends(Authorize, scopes=["profile:update"], roles = ['user'] )
):
    // do something 

    pass

```
