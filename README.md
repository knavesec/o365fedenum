Does Office365 user enumeration based on correlated HTTP response analysis.

Process:
1. Submit 5 requests for invalid users (random strings), create a baseline of what indicates an invalid user response
2. Submit a request for a known valid user (point of contact, etc), compare the response to the invalid responses and determine a baseline for what indicates a valid user response
3. Submit test user responses, compare with known valid/invalid responses to determine the status of the user


```
python3 o365fedenum.py --testfile unknown_user_list.txt --valid known_valid_username --domain tenant_domain.com --verbose
```


A few notes:
* If you repeat the spray with the same valid user in a short time frame, sometimes you'll get a "RepeatedBadPassword" variable in your "indicates valid" response. This indicates that the application responded _differently_ than it usually would with a normal user, since you've attempted a login with the same user multiple times. T*This can skew your results*. Wait a few hours then try again.
* This hasn't be _super_ thoroughly tested, though it does appear to be generally consistent. This also does work for Managed environments, but using CredMaster for MSOL spraying will yield better/more consistent data
* The users in the `testfile` and the `valid` flags don't need the `@domain.com` in them, but they can if they want. Script will check if the domain is attached and append if it isn't 
