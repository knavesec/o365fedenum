Does Office365 user enumeration based on correlated HTTP response analysis, as shown at Way West Hackin' Fest 2022

Process:
1. Submit 5 requests for invalid users (random strings), create a baseline of what indicates an invalid user response
2. Submit a request for a known valid user (point of contact, etc)
3. Compare the response to the invalid responses and determine a baseline for what indicates a valid user response
4. Submit test user responses, compare with known valid/invalid responses to determine the status of the user


```
python3 o365fedenum.py --testfile unknown_user_list.txt --valid known_valid_username --domain tenant_domain.com --verbose
```

![screenshot](https://raw.githubusercontent.com/knavesec/o365fedenum/master/screenshot.png)


A few notes:
* This _does_ make an authentication request against the username tested (RNG password), keep this in mind
* This does appear to be generally consistent across environments, but if not please let me know. This also does work for Managed environments, but there are far better methods of achieving better results without authentication requests
* The users in the `testfile` and the `valid` flags don't need the `@domain.com` in them, but they can if they want. Script will check if the domain is attached and append if it isn't
