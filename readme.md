### User Api

## Endpoints

# /login

    body:{
        
        email:string,
        password:string
    }

# /signup

    body:{
        name:string,
        email:string,
        password:string,
    }

# /home

    headers.authorisation[
        "${jwtToken}"
    ]