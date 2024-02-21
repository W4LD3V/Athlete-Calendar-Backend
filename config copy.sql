-- Create users table first as it is referenced by other tables
CREATE TABLE public.users (
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    name varchar(100) NOT NULL,
    surname varchar(100) NOT NULL,
    email varchar(100) NOT NULL,
    "password" varchar(255) NOT NULL,
    picture text NULL,
    is_organizer BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_pkey PRIMARY KEY (id)
);

-- Then create organizers table, which references the users table
CREATE TABLE public.organizers (
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    "name" varchar(100) NOT NULL,
    contact_info varchar(255) NOT NULL,
    picture text NULL,
    description text NULL,
    user_id uuid NULL,
    CONSTRAINT organizers_pkey PRIMARY KEY (id),
    CONSTRAINT organizers_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id)
);

-- Next, create the events table, which references the organizers table
CREATE TABLE public.events (
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    title varchar(255) NOT NULL,
    date_start date NOT NULL,
    date_end date NULL,
    "location" varchar(255) NOT NULL,
    organizer_id uuid NULL,
    activitytype varchar(100) NOT NULL,
    description text NULL,
    gpx text NULL,
    visibility_date date NOT NULL,
    picture text NULL,
    CONSTRAINT events_pkey PRIMARY KEY (id),
    CONSTRAINT events_organizer_id_fkey FOREIGN KEY (organizer_id) REFERENCES public.organizers(id)
);

-- The rest of the tables can be created in any order as they depend on the above tables
CREATE TABLE public.user_friends (
    user_id uuid NOT NULL,
    friend_id uuid NOT NULL,
    CONSTRAINT user_friends_pkey PRIMARY KEY (user_id, friend_id),
    CONSTRAINT user_friends_friend_id_fkey FOREIGN KEY (friend_id) REFERENCES public.users(id),
    CONSTRAINT user_friends_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id)
);

CREATE TABLE public.messages (
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    sender_id uuid NULL,
    receiver_id uuid NULL,
    message text NOT NULL,
    "timestamp" timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT messages_pkey PRIMARY KEY (id),
    CONSTRAINT messages_receiver_id_fkey FOREIGN KEY (receiver_id) REFERENCES public.users(id),
    CONSTRAINT messages_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES public.users(id)
);

CREATE TABLE public.user_going_events (
    user_id uuid NOT NULL,
    event_id uuid NOT NULL,
    CONSTRAINT user_going_events_pkey PRIMARY KEY (user_id, event_id),
    CONSTRAINT user_going_events_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id),
    CONSTRAINT user_going_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id)
);

CREATE TABLE public.user_saved_events (
    user_id uuid NOT NULL,
    event_id uuid NOT NULL,
    CONSTRAINT user_saved_events_pkey PRIMARY KEY (user_id, event_id),
    CONSTRAINT user_saved_events_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id),
    CONSTRAINT user_saved_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id)
);

CREATE TABLE public.user_settings (
    user_id uuid NOT NULL,
    notifications bool NULL DEFAULT true,
    privacy varchar(50) NULL DEFAULT 'PUBLIC'::character varying,
    CONSTRAINT user_settings_pkey PRIMARY KEY (user_id),
    CONSTRAINT user_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id)
);

CREATE TABLE public.friend_requests (
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    sender_id uuid NOT NULL,
    receiver_id uuid NOT NULL,
    status varchar(50) NOT NULL DEFAULT 'PENDING',
    sent_timestamp timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    response_timestamp timestamp NULL,
    CONSTRAINT friend_requests_pkey PRIMARY KEY (id),
    CONSTRAINT friend_requests_receiver_id_fkey FOREIGN KEY (receiver_id) REFERENCES public.users(id),
    CONSTRAINT friend_requests_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES public.users(id),
    CONSTRAINT friend_requests_unique UNIQUE (sender_id, receiver_id)
);

CREATE TABLE public.user_roles (
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    user_id uuid NOT NULL,
    role varchar(50) NOT NULL,
    CONSTRAINT user_roles_pkey PRIMARY KEY (id),
    CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id)
);
