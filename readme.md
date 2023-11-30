# Introduction  
#This project is about designing an access control schema for the San Jose State Library where we are tasked to make a simple webpage to register users, authenticate them, and allow them certain privileges to perform their tasks. We will be implementing the Role Based Access Control model, or RBAC, for this library which allows users to access certain controls based on their roles whether they are the Head Librarian, or a general librarian staff, or a student. Behind the scenes of our webpage, we will have a database to store user account information and provide simple hashes in the case where two users have identical passwords. 
#The instance folder is used to store the database, if you want to start a fresh database, then delete "site.db"  
  
#This program was with large help from ChatGPT for the code and debugging process.  
#All links to my Chat sessions will be provided below:  
https://chat.openai.com/share/ebf6cb13-b75d-4aa0-9f3d-c7ab89eb1800  
https://chat.openai.com/share/fcf21c68-0b1f-4d71-a39f-9a9430c07dad  
https://chat.openai.com/share/aa2ddab7-5986-4fa3-947a-a3cea29120bb  
  
# Prerequisite  
#install python3  
winget install python3  
  
# Flask and its libraries  
pip install Flask Flask-WTF Flask-Login Flask-Bcrypt Flask-SQLAlchemy
  
#run  
python app.py  
  
#To view the webpage. Go to 127.0.0.1:5000 in your browser's address bar.  
  
#we are using SQLite for our database  
#you can read the SQL database using  
winget install SQLite.SQLite  
sqlite3 site.db  
.tables  
.dump  
