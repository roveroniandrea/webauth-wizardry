# Web-auth Wizardry
This repository contains experiments related to authentication and authorization between web server and clients.

# Why
Main purpose of this repo is to better understand how different authentication flows work, to experiment with them, and (possibly) to provide some ready-to-use code to ~~steal~~ borrow and past in other projects.

# Disclaimer
THE OWNER OF THIS REPOSITORY DISCLAIMS ANY RESPONSIBILITY FOR THE USE OR CONSEQUENCES OF USING THIS CODE. IT IS RECOMMENDED TO CAREFULLY EVALUATE AND ADAPT THE CODE TO YOUR OWN NEEDS AND SECURITY STANDARDS.



# High level flow
This repo will start by using [PassportJS](https://www.passportjs.org/) and some of its Strategies.
In order to be as clean and easy to understand as possible, this code will try to separate things that can be made independently, giving flexibility to use different flows and/or integrating them together.

Main ares will be:
- `Authentication`: Allows a user to receive a trusted identity. In order to do so, the user needs to resolve a challenge, its data needs to be created or fetched from the database, and optionally some other checks can be applied. 

    This will be further divided into some steps:
    - `Authenticating`: Providing some sort of "proof" regarding the user that wants to sign-in, like a username/password or third party providers
    - `Data fetching and constraints`: Retrieving user infos from a database and applying optional checks, like banned users or already active sessions
    - `Providing the identity to the client`: Now that the server has asserted the user identity, it needs to make so that the client can make further request with this identity. For this scope, JWT and/or cookies can be used. In addition, this identity needs to be retrived on every request

- `Authorization`: On each request made by the client, the server needs to assert that the user (or the identity) has the required permissions to access a certain resource, or to call that endpoint, or in general to do any action.


## See dependencies
`npx ts_dependency_graph --start src/index.ts --graph_folder | dot -T svg > dependencygraph.svg`