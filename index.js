require('dotenv').config();
const express = require("express");
const app = express();
const port = 3000;
const cors = require("cors");
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const pgp = require("pg-promise")();

const authenticateJWT = require('./middleware/jwt-authenticate')

// Connect to your PostgreSQL database
const db = pgp({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
});

app.use(cors());
app.use(express.json());

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        // Retrieve user with the given email
        const user = await db.oneOrNone('SELECT * FROM public.users WHERE email = $1', [email]);

        // If user not found or password is incorrect
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        // Check if the user has an organization
        const hasOrganization = await db.one('SELECT EXISTS(SELECT 1 FROM public.organizers WHERE user_id = $1)', [user.id]);

        // User is valid, generate a JWT token
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
            expiresIn: '1h' // Token expiration time
        });

        // Send token and organization status back to the client
        res.json({ token, is_organizer: user.is_organizer, hasOrganization: hasOrganization.exists });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
});

app.post("/signup", async (req, res) => {
    const { email, password, name, surname, type } = req.body;
    let is_organizer = false;

    if (!name || !surname || !email || !password) {
        return res.status(400).json({ message: "Name, surname, email, password are required" });
      }
    
      if (type && type.toLowerCase() === "organizer"){
        is_organizer = true;
    }

    try {
        // Check if the email is already registered
        const existingUser = await db.oneOrNone('SELECT * FROM public.users WHERE email = $1', [email]);

        if (existingUser) {
            return res.status(409).json({ message: "Email already registered" });
        }

        // Hash the password before storing it
        const hashedPassword = bcrypt.hashSync(password, 10);  // '10' is the number of rounds for salt generation

        // Start a database transaction
        await db.tx(async t => {
            // Store the new user's details in the database with the hashed password
            const user = await t.one('INSERT INTO public.users (name, surname, email, password, is_organizer) VALUES ($1, $2, $3, $4, $5) RETURNING id', [name, surname, email, hashedPassword, is_organizer]);
            
            // Create a default settings record for the new user
            await t.none('INSERT INTO public.user_settings (user_id, privacy) VALUES ($1, $2)', [user.id, 'PUBLIC']);
        });

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
});

app.delete("/remove-user", authenticateJWT, async (req, res) => {
    try {
        const userId = req.userId;

        // Check if the user exists
        const existingUser = await db.oneOrNone('SELECT * FROM public.users WHERE id = $1', userId);
        if (!existingUser) {
            return res.status(404).json({ message: "User not found!" });
        }

        // Delete or update records in dependent tables
        await db.none('DELETE FROM public.user_friends WHERE user_id = $1 OR friend_id = $1', userId);
        await db.none('DELETE FROM public.messages WHERE sender_id = $1 OR receiver_id = $1', userId);
        await db.none('DELETE FROM public.user_going_events WHERE user_id = $1', userId);
        await db.none('DELETE FROM public.user_saved_events WHERE user_id = $1', userId);
        await db.none('DELETE FROM public.user_settings WHERE user_id = $1', userId);
        await db.none('DELETE FROM public.friend_requests WHERE sender_id = $1 OR receiver_id = $1', userId);

        // Finally, delete the user
        await db.none('DELETE FROM public.users WHERE id = $1', userId);

        res.status(200).json({ message: "User deleted successfully" });
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});


app.get('/events',authenticateJWT, async (req, res) => {
    try {
        const events = await db.any('SELECT * FROM events');
        res.json(events);
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

app.get('/events/:eventId', authenticateJWT, async (req, res) => {
    try {
        const eventId = req.params.eventId;
        const userId = req.userId; // Assuming req.user.id contains the ID of the requester after successful authentication
        
        const events = await db.any(`
            SELECT 
                events.*, 
                organizers.name AS organizer_name, 
                (SELECT COUNT(*) FROM user_saved_events WHERE event_id = events.id) AS saved_count,
                (SELECT COUNT(*) 
                    FROM user_saved_events 
                    INNER JOIN user_friends ON user_saved_events.user_id = user_friends.friend_id 
                    WHERE user_saved_events.event_id = events.id AND user_friends.user_id = $2) AS friends_saved_count
            FROM events 
            LEFT JOIN organizers ON events.organizer_id = organizers.id 
            WHERE events.id = $1
        `, [eventId, userId]);
        
        res.json(events);
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

app.get('/organizer', authenticateJWT, async (req, res) => {
    try {
        const userId = req.userId
        const organizer = await db.one('SELECT * FROM organizers WHERE user_id = $1', [userId]);
        res.json(organizer);
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});


app.get('/organizer/:id', authenticateJWT, async (req, res) => {
    try {
        const organizerId = req.params.id;
        const organizer = await db.one('SELECT name FROM organizers WHERE id = $1', [organizerId]);
        res.json(organizer);
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});


app.get('/saved-events', authenticateJWT, async (req, res) => {
    try {
        const userId = req.userId;

        const events = await db.any(`
            SELECT events.* 
            FROM events
            JOIN user_saved_events ON events.id = user_saved_events.event_id
            WHERE user_saved_events.user_id = $1
        `, [userId]);

        res.json(events);
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

app.get('/user', authenticateJWT, async (req, res) => {
    try {
        const userId = req.userId;

        const user = await db.oneOrNone('SELECT id, name, surname, email, picture FROM users WHERE id = $1', [userId]);

        if (user) {
            res.json(user);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

app.post("/updateProfile", async (req, res) => {
    // Extract the token from the Authorization header
    const token = req.headers.authorization.split(" ")[1]; // Assuming Bearer token is sent
    let decoded;
    try {
        // Decode the token to get the user ID
        decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        return res.status(401).json({ message: "Invalid token" });
    }

    const userId = decoded.id;
    const { name, surname, email } = req.body;

    let fieldsToUpdate = [];
    let valuesToUpdate = [];
    
    if (name !== undefined) {
        fieldsToUpdate.push('name');
        valuesToUpdate.push(name);
    }

    if (surname !== undefined) {
        fieldsToUpdate.push('surname');
        valuesToUpdate.push(surname);
    }

    if (email !== undefined) {
        fieldsToUpdate.push('email');
        valuesToUpdate.push(email);
    }

    // If no fields to update, return an error or a message
    if (fieldsToUpdate.length === 0) {
        return res.status(400).json({ message: "No fields provided for update" });
    }

    // Construct the SQL query dynamically
    const updateQuery = `UPDATE public.users SET ${fieldsToUpdate.map((field, index) => `${field} = $${index + 1}`).join(', ')} WHERE id = $${fieldsToUpdate.length + 1}`;
    
    try {
        // Execute the dynamic update query
        await db.none(updateQuery, [...valuesToUpdate, userId]);
        res.status(200).json({ message: "Profile updated successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
});


app.post("/changePassword", async (req, res) => {
    const token = req.headers.authorization.split(" ")[1]; // Assuming Bearer token is sent
    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        return res.status(401).json({ message: "Invalid token" });
    }

    const userId = decoded.id;
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
        return res.status(400).json({ message: "Old and new passwords are required" });
    }

    try {
        // Fetch the user's current password hash from the database
        const user = await db.one('SELECT password FROM public.users WHERE id = $1', [userId]);
        const isMatch = await bcrypt.compare(oldPassword, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: "Old password is incorrect" });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the user's password in the database
        await db.none('UPDATE public.users SET password = $1 WHERE id = $2', [hashedPassword, userId]);

        res.status(200).json({ message: "Password changed successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
});



app.post("/save-event", authenticateJWT, async (req, res) => {
    try {
        // Extract user ID from the authenticated request
        const userId = req.userId;

        // Extract event ID from the request body
        const { event_id } = req.body;

        // Check if the event is already saved for this user
        const existingEvent = await db.oneOrNone('SELECT * FROM public.user_saved_events WHERE user_id = $1 AND event_id = $2', [userId, event_id]);

        if (existingEvent) {
            return res.status(409).json({ message: "Event already saved for this user" });
        }

        // Save the event for the user
        await db.none('INSERT INTO public.user_saved_events (user_id, event_id) VALUES ($1, $2)', [userId, event_id]);

        res.status(201).json({ message: "Event saved successfully" });
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});


app.delete("/unsave-event/:eventId", authenticateJWT, async (req, res) => {
    try {
        // Extract user ID from the authenticated request
        const userId = req.userId;

        // Extract event ID from the URL parameters
        const eventId = req.params.eventId;

        // Check if the event is saved for this user
        const existingEvent = await db.oneOrNone('SELECT * FROM public.user_saved_events WHERE user_id = $1 AND event_id = $2', [userId, eventId]);

        // If the event isn't saved for this user, return an error
        if (!existingEvent) {
            return res.status(404).json({ message: "Event not found for this user" });
        }

        // Delete the event for the user
        await db.none('DELETE FROM public.user_saved_events WHERE user_id = $1 AND event_id = $2', [userId, eventId]);

        res.status(200).json({ message: "Event unsaved successfully" });
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

app.post('/send-friend-request', authenticateJWT, async (req, res) => {
    const userId = req.userId; // Sender's ID
    const { friendId } = req.body; // Receiver's ID

    try {
        // Check if a friend request already exists
        const existingRequest = await db.oneOrNone('SELECT * FROM public.friend_requests WHERE sender_id = $1 AND receiver_id = $2', [userId, friendId]);

        if (existingRequest) {
            return res.status(409).json({ message: "Friend request already sent" });
        }

        // Check if the users are already friends
        const existingFriend = await db.oneOrNone('SELECT * FROM public.user_friends WHERE user_id = $1 AND friend_id = $2', [userId, friendId]);

        if (existingFriend) {
            return res.status(409).json({ message: "Users are already friends" });
        }

        // Add a friend request
        await db.none('INSERT INTO public.friend_requests (sender_id, receiver_id) VALUES ($1, $2)', [userId, friendId]);

        res.status(201).json({ message: "Friend request sent successfully" });
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});


app.post('/accept-friend-request', authenticateJWT, async (req, res) => {
    const userId = req.userId; // Receiver's ID (the one accepting the request)
    const { friendId } = req.body; // Sender's ID (the one who sent the request)

    try {
        // Update the friend request status to 'ACCEPTED'
        const updateRequest = await db.none('UPDATE public.friend_requests SET status = $1, response_timestamp = CURRENT_TIMESTAMP WHERE receiver_id = $2 AND sender_id = $3 AND status = $4', ['ACCEPTED', userId, friendId, 'PENDING']);

        // Add to the user_friends table
        await db.none('INSERT INTO public.user_friends (user_id, friend_id) VALUES ($1, $2), ($2, $1)', [userId, friendId]);

        res.status(200).json({ message: "Friend request accepted successfully" });
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});


app.post('/send-message', authenticateJWT, async (req, res) => {
    const senderId = req.userId;
    const { receiver_id, message } = req.body; // Corrected to match the payload

    try {
        await db.none('INSERT INTO public.messages (sender_id, receiver_id, message) VALUES ($1, $2, $3)', [senderId, receiver_id, message]);
        res.status(201).json({ message: "Message sent successfully" });
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});


app.get('/retrieve-messages', authenticateJWT, async (req, res) => {
    const userId = req.userId; // One of the users
    const { friendId } = req.query; // The other user

    try {
        const query = `
            SELECT 
                m.id, 
                m.sender_id, 
                m.receiver_id, 
                m.message, 
                m.timestamp, 
                sender.name AS sender_name, 
                sender.surname AS sender_surname, 
                receiver.name AS receiver_name, 
                receiver.surname AS receiver_surname
            FROM 
                public.messages m
            INNER JOIN 
                public.users sender ON m.sender_id = sender.id
            INNER JOIN 
                public.users receiver ON m.receiver_id = receiver.id
            WHERE 
                (m.sender_id = $1 AND m.receiver_id = $2) OR 
                (m.sender_id = $2 AND m.receiver_id = $1) 
            ORDER BY 
                m.timestamp ASC`;

        const messages = await db.any(query, [userId, friendId]);
        res.json(messages);
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});


app.get('/friend-requests', authenticateJWT, async (req, res) => {
    const userId = req.userId; // Receiver's ID

    try {
        const requests = await db.manyOrNone(
            'SELECT fr.sender_id, u.name as sender_name FROM public.friend_requests fr ' +
            'JOIN public.users u ON fr.sender_id = u.id ' +
            'WHERE fr.receiver_id = $1 AND fr.status = $2', [userId, 'PENDING']
        );

        res.status(200).json(requests);
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

app.get('/search-users', authenticateJWT, async (req, res) => {
    const { query } = req.query;

    try {
        const users = await db.manyOrNone(
            'SELECT u.id, u.name, u.email FROM public.users u ' +
            'JOIN public.user_settings us ON u.id = us.user_id ' +
            'WHERE (LOWER(u.name) LIKE LOWER($1) OR LOWER(u.email) LIKE LOWER($1)) ' +
            'AND us.privacy = $2', [`%${query}%`, 'PUBLIC']
        );
 
        res.status(200).json(users);
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

app.get("/friends", authenticateJWT, async (req, res) => {
    const userId = req.userId

    try {
        const friends = await db.manyOrNone(
            'SELECT u.id, u.name, u.email FROM public.users u ' +
            'INNER JOIN public.user_friends uf ON u.id = uf.friend_id OR u.id = uf.user_id ' +
            'WHERE (uf.user_id = $1 OR uf.friend_id = $1) AND u.id != $1', 
            [userId]
        );

        res.status(200).json(friends);
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

app.get('/user-settings', authenticateJWT, async (req, res) => {
    try {
        const userId = req.userId;

        const settings = await db.oneOrNone('SELECT * FROM public.user_settings WHERE user_id = $1', [userId]);

        if (settings) {
            res.json(settings);
        } else {
            res.status(404).json({ message: 'Settings not found' });
        }
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

app.post('/update-user-settings', authenticateJWT, async (req, res) => {
    const userId = req.userId;
    const { notifications, privacy } = req.body;

    try {
        await db.none('UPDATE public.user_settings SET notifications = $1, privacy = $2 WHERE user_id = $3', [notifications, privacy, userId]);

        res.status(200).json({ message: "Settings updated successfully" });
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const multer = require('multer');
const stream = require('stream');

// AWS S3 client configuration
const s3Client = new S3Client({
    region: process.env.AWS_REGION,
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    }
  });  

// Multer upload storage configuration
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Not an image! Please upload only images.'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 1024 * 1024 * 5 // 5 MB
  }
});

app.post("/uploadProfilePicture", authenticateJWT, upload.single('picture'), async (req, res) => {
    if (!req.file) {
      return res.status(400).send('No file uploaded.');
    }
  
    // Ensure that this variable is correctly being set to the current user's ID
    const userId = req.userId; 

    const file = req.file;
    const key = `${Date.now().toString()}.${file.originalname.split('.').pop()}`;
  
    const uploadParams = {
      Bucket: 'athlete-calendar',
      Key: key,
      Body: file.buffer,
      ContentType: file.mimetype
    };
  
    try {
      const command = new PutObjectCommand(uploadParams);
      await s3Client.send(command);
      const picturePath = `https://${uploadParams.Bucket}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;
  
    console.log('Attempting to update user picture with path:', picturePath);
    console.log('User ID:', userId);
      // Perform the database update logic
      await db.none('UPDATE public.users SET picture = $1 WHERE id = $2', [picturePath, userId])
        .then(() => {
          console.log('Database updated successfully for user:', userId);
          res.json({ message: "Profile picture updated successfully", path: picturePath });
        })
        .catch(error => {
            console.error('Error updating database:', error);
            res.status(500).json({ error: 'Error updating database', details: error.message });
        });          
    } catch (error) {
      console.error("Error uploading to S3:", error);
      res.status(500).json({ error: 'Error occurred during upload to S3' });
    }
  });
  
  app.post("/create-organizer", authenticateJWT, async (req, res) => {
    const { name, description, contact_info, picture } = req.body;
    const userId = req.userId;

    if (!name || !description || !contact_info ) {
        return res.status(400).json({ message: "Name, description, contact information are required." });
    }

    try {
        // Check if the user is allowed to create an organizer
        const user = await db.oneOrNone('SELECT is_organizer FROM public.users WHERE id = $1', [userId]);
        if (!user || !user.is_organizer) {
            return res.status(403).json({ message: "User is not authorized to create an organizer." });
        }

        // Check if organizer already exists
        const existingOrganizer = await db.oneOrNone('SELECT * FROM public.organizers WHERE name = $1', [name]);
        if (existingOrganizer) {
            return res.status(409).json({ message: "This title for an organizer is already registered within the system." });
        }

        // Insert new organizer
        await db.none('INSERT INTO public.organizers (name, description, contact_info, user_id, picture ) VALUES ($1, $2, $3, $4, $5)', [name, description, contact_info, userId, picture]);
        res.status(201).json({ message: "Organizer registered successfully." });
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

app.get('/organization-events', authenticateJWT, async (req, res) => {
    try {
        const userId = req.userId;
        console.log("userId:", userId);
    
        const queryString = `
            SELECT events.*, organizers.contact_info 
            FROM events
            JOIN organizers ON events.organizer_id = organizers.id
            WHERE organizers.user_id = $1        
        `;
        console.log("Query String:", queryString);
    
        const events = await db.any(queryString, [userId]);
        console.log("Events:", events);
    
        res.json(events);
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

app.post("/organization-events", authenticateJWT, async (req, res) => {
    let { title, date_start, date_end, location, activityType, description, gpx, visibility_date, picture } = req.body;
    const userId = req.userId;

    if (!title || !date_start || !date_end || !location || !activityType || !description) {
        return res.status(400).json({ message: "Title, start date, end date, location, activity type, and description are required." });
    }

    // Set default values for gpx and picture if not provided
    gpx = gpx || null;
    picture = picture || null;

    // Set visibility_date to current Unix timestamp if not provided
    if (!visibility_date) {
        visibility_date = Math.floor(Date.now() / 1000); // Convert current date to Unix timestamp
    }

    try {
        // Check if the user is allowed to create an event
        const user = await db.oneOrNone('SELECT is_organizer FROM public.users WHERE id = $1', [userId]);
        if (!user || !user.is_organizer) {
            return res.status(403).json({ message: "User is not authorized to create an event." });
        }

        // Check if event already exists
        const existingEvent = await db.oneOrNone('SELECT * FROM public.events WHERE title = $1', [title]);
        if (existingEvent) {
            return res.status(409).json({ message: "This title for an event is already registered within the system." });
        }

        // Get the organizer_id based on the user_id
        const organizer = await db.one('SELECT id FROM public.organizers WHERE user_id = $1', [userId]);

        // Insert new event with the correct organizer_id
        await db.none('INSERT INTO public.events (title, date_start, date_end, location, organizer_id, activityType, description, gpx, visibility_date, picture) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)',
            [title, date_start, date_end, location, organizer.id, activityType, description, gpx, visibility_date, picture]);

        res.status(201).json({ message: "Event created successfully." });
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});


app.delete("/organization-events/:eventId", authenticateJWT, async (req, res) => {
    try {
        // Extract user ID from the authenticated request
        const userId = req.userId;

        // Extract event ID from the URL parameters
        const eventId = req.params.eventId;

        // Check if the event is saved for this user
        const existingEvent = await db.oneOrNone('SELECT * FROM public.events WHERE id = $1', [eventId]);

        // If the event isn't saved for this user, return an error
        if (!existingEvent) {
            return res.status(404).json({ message: "Event not found for this user" });
        }

        // Delete the event for the user
        await db.none('DELETE FROM public.events WHERE id = $1', [eventId]);

        res.status(200).json({ message: "Event unsaved successfully" });
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});

app.delete("/remove-organization", authenticateJWT, async (req, res) => {
    try {
        const userId = req.userId;

        // Find the organization associated with the user
        const organization = await db.oneOrNone('SELECT * FROM public.organizers WHERE user_id = $1', userId);
        if (!organization) {
            return res.status(404).json({ message: "Organization not found for the user!" });
        }
        const organizationId = organization.id;

        // Delete events organized by this organization
        await db.none('DELETE FROM public.events WHERE organizer_id = $1', organizationId);

        // Handle other dependencies here if needed

        // Finally, delete the organization
        await db.none('DELETE FROM public.organizers WHERE id = $1', organizationId);

        res.status(200).json({ message: "Organization deleted successfully" });
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});



app.get('/friend-information/:friendId', authenticateJWT, async (req, res) => {
    const { friendId } = req.params; // Using route parameter

    try {
        const user_information = await db.oneOrNone('SELECT name FROM users WHERE id = $1', [friendId]);
        if (user_information) {
            res.json(user_information);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ error: 'Database query error' });
    }
});


app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
