# ThingsApi

## TL;DR

```bash
dotnet run
```

Create a user by sending a POST request with the following JSON body

```json
{
    "username": "some@email.com",
    "password": "whatever"
}
```

to https://localhost:5001/api/users

Then retrieve a JWT by posting the same json to https://localhost:5001/api/users/token



https://localhost:5001/api/values will give 401 unauthorized unless you provide a valid token




## Something

Using dotnet new webapi as starting point

Manually adding Identity and Entity Framework.

JWT-related stuff

Sorry if anyone is actually reading this README and hoping for details. Feel free to contact me.

## Commands

If there is no app.db run the following command from this folder

```bash
dotnet ef database update
```