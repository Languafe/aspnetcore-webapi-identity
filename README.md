# aspnetcore-webapi-identity

ASP.NET Core 2.2 Web Api thing

The "webapi" template (dotnet new) thus far hasn't had the option to include authentication, as the "mvc" template does if you use the --auth switch

```bash
dotnet new mvc --auth Individual
```

With this project I try to bring various pieces together with the following goal in mind:

Creating an ASP.NET Core Web Api that enables user registration, and makes use of ASP.NET Core Identity.

The api should showcase JWT authentication, and role-based authorization.

Platform agnostic, I want to run the application without any changes on both Linux and Windows hosts. I don't own a MacBook :'( but it would probably run there as well.
