
Python script to generate universis access tokens without oauth2

## Example:

```bash
$ pip install AUTh-authenticator
```

```python
from AUTh_authenticator import universis

universis.generate_token("username", "password")
# "eyJhjGciOvJSUzI1NiIzInR5cCI..."

```
