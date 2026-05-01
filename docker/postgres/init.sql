-- Supply Chain Risk Intelligence — PostgreSQL initialization
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
GRANT ALL PRIVILEGES ON DATABASE supplychain_db TO sc_user;
