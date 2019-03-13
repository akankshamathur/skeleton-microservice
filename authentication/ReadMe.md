###Configure Mongodb Database for this project
## If user has already been created in admin database, skip to step 8.
* Start Mongo Console using **mongo**
* Change the database and select admin **use admin**
* Use Admin database **db.createUser({user:"root",pwd:"nextdefault",roles:[{role:"userAdminAnyDatabase",db:"admin"}]})**
* Close the Mongo Console using **exit** or **Ctrl^D**
* sudo vim /etc/mongod.conf
* Uncomment the security and add security: authorization: "enabled" **Since It follows YML Configuration so format it accordingly**
* Open mongo console with secure login **mongo -u secure_user -p --authenticationDatabase admin** and give your **secure_password**.
* Create a database kidsventure using **use kidsventure**
* Create a user to access the kidsventure database **db.createUser({user:'secure_user',pwd:'secure_password',roles:[{role:'readWrite',db:'kidsventure'}]});**