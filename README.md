# Athlete Calendar - Platform for sports events enthusiasts and organizers

#### Video Demo: https://youtu.be/FVPnNtJor8E


#### Description:

Athlete Calendar is a platform for sports event organizers and sports enthusiasts to search for upcoming local sports events, and communicate with their friends. 


#### Features:

1. **Event viewing by filtering them out by selected location, date, activity & organizer:**
Users can view upcoming sports events by tailoring search results to their liking.
2. **Saving events:** The website provides a feature for users to save & track selected events.
3. **Personalization % communication:** The application utilizes authentication su users can create, delete & update their account, and find other friends & chat with them.
4. **User Authentication:** To ensure data privacy, the app implements password hashing using Werkzeug's security library for user authentication.
5. **Platform for organizers:** Sports event organizers are able to register and post upcoming events fro other users to see.
5. **Minimalistic Design:** The app's design focuses on simplicity and ease of use, providing users with a clean and intuitive interface to make the event logging process hassle-free.

#### Challenges Faced:

During development, one of the main challenges was to display data in different relations and properly link events to specific events. To overcome this, the project employed table joins in SQL to establish the necessary connections between the event data and saved details.

#### Technologies Used:

1. Node.js: The web application is built using Node.js, a back-end framework in Javascript, to handle routing and HTTP requests.
2. PostgreSQL: This dependency is utilized to make node.js interact with the database, allowing for efficient storage and retrieval of events and user data.
3. JWT: Used for password hashing to securely store user credentials in the database.
4. JavaScript: To enhance the user experience, JavaScript is incorporated to generate interactive charts for visualizing workout progress.
5. Bootstrap: The app utilizes Bootstrap's CSS styling to maintain a simple and aesthetically pleasing design.


#### Design Choices:

The design of the Athlete Calendar prioritizes simplicity and usability, as the main objective was to create a user-friendly and minimalistic calendar. Bootstrap was chosen for its responsive layout and pre-designed components, which allowed for quicker development and ensured a consistent look across different devices.


#### Instructions:

To run the Workout Logger, follow these steps:  

1. Ensure you have Node.js installed on your system.
2. Clone the project repository to your local machine.
3. Open a terminal and navigate to the project directory.
4. Run `npm install` to install the needed dependencies.
5. Set up the PostgreSQL database by running the provided commands in the config.sql file.
6. Set up the .env variables depending on your PostgreSQL server.
7. Execute the command `npm start ` to start the Flask development server.
8. Access the application by navigating to http://localhost:3000 in your web browser.

#### Additional Information:

The Athlete Calendar was developed as part of a personal project to enhance programming skills while building a practical and useful application. The app is still a work in progress, and future updates may include more features, such as workout plan customization and social sharing capabilities. Feedback and suggestions are always welcome to improve the app further.
