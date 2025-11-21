"""
NON-COMPLIANT SCIM 2.0 SERVER
=============================

RFC Compliance Status:
- RFC 7642 (SCIM Definitions): ✓ Concepts understood
- RFC 7643 (Core Schema): ✓ User and Group schemas implemented
- RFC 7644 (SCIM Protocol): ✓ HTTP methods, error responses, PATCH operations
- RFC 9865 (Cursor Pagination): ○ Not implemented (optional)

INTENTIONAL NON-COMPLIANCE:
1. Member Addition Failure (Simulates Snowflake):
   - POST /Groups with members → 400 Bad Request
   - PATCH /Groups/{id} to add members → 400 Bad Request
   - Reason: Cannot verify member existence without user database

2. Group Rename Failure (Simulates Microsoft):
   - PATCH /Groups/{id} to change displayName → 409 Conflict
   - Reason: Group renames not supported

These behaviors are INTENTIONALLY BROKEN for testing purposes.
"""

import uuid
from flask import Flask, request, jsonify
import sys
import os

app = Flask(__name__)

# --- Configuration and In-Memory Storage ---

API_TOKEN = "SCIM_TOKEN"
SCIM_BASE_URL = "/scim/v2"

groups = {}

# In-memory user store - starts empty, accepts any users pushed by Okta
# When Okta provisions users via POST/PUT, they'll be stored here
# This allows Okta to attempt member operations (which we'll reject - non-compliant behavior)
users = {}

# --- Hardcoded SCIM Discovery Resources ---

USER_SCHEMA = {
    "id": "urn:ietf:params:scim:schemas:core:2.0:User",
    "name": "User",
    "description": "User Account",
    "attributes": [
        {"name": "userName", "type": "string", "multiValued": False, "required": True, "caseExact": False, "mutability": "readWrite", "returned": "default", "uniqueness": "server"},
        {"name": "id", "type": "string", "multiValued": False, "required": True, "caseExact": True, "mutability": "readOnly", "returned": "always", "uniqueness": "server"},
        {"name": "displayName", "type": "string", "multiValued": False, "required": False, "caseExact": False, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
        {"name": "active", "type": "boolean", "multiValued": False, "required": False, "mutability": "readWrite", "returned": "default"},
        {"name": "emails", "type": "complex", "multiValued": True, "required": False, "mutability": "readWrite", "returned": "default",
         "subAttributes": [
             {"name": "value", "type": "string", "multiValued": False, "required": False, "caseExact": False, "mutability": "readWrite", "returned": "default"},
             {"name": "primary", "type": "boolean", "multiValued": False, "required": False, "mutability": "readWrite", "returned": "default"}
         ]},
        {"name": "name", "type": "complex", "multiValued": False, "required": False, "mutability": "readWrite", "returned": "default",
         "subAttributes": [
             {"name": "givenName", "type": "string", "multiValued": False, "required": False, "caseExact": False, "mutability": "readWrite", "returned": "default"},
             {"name": "familyName", "type": "string", "multiValued": False, "required": False, "caseExact": False, "mutability": "readWrite", "returned": "default"}
         ]}
    ],
    "meta": {"resourceType": "Schema", "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"}
}

GROUP_SCHEMA = {
    "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
    "name": "Group",
    "description": "Group",
    "attributes": [
        {"name": "displayName", "type": "string", "multiValued": False, "required": True, "caseExact": False, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
        {"name": "id", "type": "string", "multiValued": False, "required": True, "caseExact": True, "mutability": "readOnly", "returned": "always", "uniqueness": "server"},
        {"name": "members", "type": "complex", "multiValued": True, "required": False, "mutability": "readWrite", "returned": "default",
         "subAttributes": [
             {"name": "value", "type": "string", "multiValued": False, "required": False, "caseExact": True, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
             {"name": "display", "type": "string", "multiValued": False, "required": False, "caseExact": False, "mutability": "readWrite", "returned": "default", "uniqueness": "none"}
         ]}
    ],
    "meta": {"resourceType": "Schema", "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group"}
}

USER_RESOURCETYPE = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
    "id": "User",
    "name": "User",
    "endpoint": "/scim/v2/Users",
    "description": "User Account",
    "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
    "meta": {"location": "/scim/v2/ResourceTypes/User", "resourceType": "ResourceType"}
}

GROUP_RESOURCETYPE = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
    "id": "Group",
    "name": "Group",
    "endpoint": "/scim/v2/Groups",
    "description": "Group",
    "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
    "meta": {"location": "/scim/v2/ResourceTypes/Group", "resourceType": "ResourceType"}
}


# --- SCIM Helper Functions ---

def scim_error(detail, status):
    error = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "detail": detail,
        "status": str(status),
    }
    return jsonify(error), status

def scim_list_response(resources):
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(resources),
        "startIndex": 1,
        "itemsPerPage": len(resources),
        "Resources": resources
    }

# --- Authentication ---

@app.before_request
def check_auth():
    # Log RAW HTTP request details
    print("\n" + "="*80, file=sys.stderr)
    print(f"RAW HTTP REQUEST: {request.method} {request.path}", file=sys.stderr)
    print("="*80, file=sys.stderr)

    # Log query parameters
    if request.args:
        print(f"QUERY PARAMS: {dict(request.args)}", file=sys.stderr)

    # Log all headers
    print("HTTP HEADERS:", file=sys.stderr)
    for header, value in request.headers:
        # Mask the token for security
        if header == 'Authorization' and value.startswith('Bearer '):
            print(f"  {header}: Bearer ***MASKED***", file=sys.stderr)
        else:
            print(f"  {header}: {value}", file=sys.stderr)

    # Log raw body for non-GET requests
    # CRITICAL: Use get_data(cache=True) to avoid consuming the stream
    # This allows the route handlers to still call get_json() later
    if request.method in ['POST', 'PATCH', 'PUT', 'DELETE']:
        if request.content_length and request.content_length > 0:
            try:
                # cache=True means Flask will cache it for later use
                body = request.get_data(as_text=True, cache=True)
                if body:
                    print(f"RAW BODY (Content-Length: {request.content_length}):", file=sys.stderr)
                    print(body, file=sys.stderr)
                else:
                    print("RAW BODY: [Empty]", file=sys.stderr)
            except Exception as e:
                print(f"RAW BODY: [Error reading: {e}]", file=sys.stderr)
        else:
            print("RAW BODY: [No content]", file=sys.stderr)
    else:
        print("RAW BODY: [GET request - no body]", file=sys.stderr)

    print("="*80 + "\n", file=sys.stderr)

    if request.path in [f"{SCIM_BASE_URL}/Schemas", f"{SCIM_BASE_URL}/ResourceTypes", "/version"]:
        return # Allow /version endpoint without authentication

    auth_header = request.headers.get("Authorization")
    expected_token = f"Bearer {API_TOKEN}"
    if not auth_header or auth_header != expected_token:
        print(f"DEBUG: Authentication failed for {request.path}", file=sys.stderr)
        return scim_error("Authentication failure: missing or invalid token.", 401)

# --- SCIM Discovery Endpoints ---

@app.route(f"{SCIM_BASE_URL}/Users", methods=['GET', 'POST'])
def handle_users():
    """List users (GET) or create a new user (POST)."""
    if request.method == 'GET':
        return get_users()
    elif request.method == 'POST':
        return create_user()

def get_users():
    """Returns users from our user store. Okta needs this to know which users exist."""
    print("="*80, file=sys.stderr)
    print("DEBUG: GET /Users - List Users", file=sys.stderr)
    print("="*80, file=sys.stderr)

    filter_query = request.args.get('filter')
    print(f"DEBUG: Filter query: {filter_query}", file=sys.stderr)

    found_users = []

    if filter_query:
        # Support filtering by userName (most common)
        if 'userName eq ' in filter_query:
            try:
                username_to_find = filter_query.split('eq ')[1].strip('"')
                for user in users.values():
                    if user.get('userName') == username_to_find:
                        found_users.append(user)
                print(f"DEBUG: Found {len(found_users)} user(s) matching userName '{username_to_find}'", file=sys.stderr)
            except IndexError:
                return scim_error("Invalid filter format", 400)
        else:
            # Return all users for other filters (we don't implement full filter support)
            found_users = list(users.values())
            print(f"DEBUG: Unsupported filter, returning all {len(found_users)} users", file=sys.stderr)
    else:
        # No filter - return all users
        found_users = list(users.values())
        print(f"DEBUG: No filter, returning all {len(found_users)} users", file=sys.stderr)

    for user in found_users:
        print(f"DEBUG:   - {user['userName']} (id: {user['id']})", file=sys.stderr)

    print("="*80, file=sys.stderr)
    return jsonify(scim_list_response(found_users)), 200

def create_user():
    """Create a new user - accepts any user Okta pushes."""
    print("="*80, file=sys.stderr)
    print("DEBUG: POST /Users - Create User Request", file=sys.stderr)
    print("="*80, file=sys.stderr)

    user_data = request.get_json(silent=True)
    print(f"DEBUG: Full request payload: {user_data}", file=sys.stderr)

    # Validate required SCIM schema
    if not user_data.get("schemas") or "urn:ietf:params:scim:schemas:core:2.0:User" not in user_data["schemas"]:
        print("DEBUG: FAILED - Invalid SCIM User schema", file=sys.stderr)
        return scim_error("Invalid SCIM User schema.", 400)

    # userName is required per RFC 7643
    if not user_data.get("userName"):
        print("DEBUG: FAILED - Missing required attribute 'userName'", file=sys.stderr)
        return scim_error("Missing required attribute 'userName'.", 400)

    # Generate a unique user ID
    user_id = str(uuid.uuid4())

    # Build the user object with metadata
    from datetime import datetime
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    new_user = {
        "schemas": user_data.get("schemas", ["urn:ietf:params:scim:schemas:core:2.0:User"]),
        "id": user_id,
        "userName": user_data["userName"],
        "active": user_data.get("active", True),
        "groups": [],  # RFC 7643: readOnly attribute
        "meta": {
            "resourceType": "User",
            "created": timestamp,
            "lastModified": timestamp,
            "location": f"{SCIM_BASE_URL}/Users/{user_id}"
        }
    }

    # Copy optional attributes if provided
    if "name" in user_data:
        new_user["name"] = user_data["name"]
    if "displayName" in user_data:
        new_user["displayName"] = user_data["displayName"]
    if "emails" in user_data:
        new_user["emails"] = user_data["emails"]
    if "externalId" in user_data:
        new_user["externalId"] = user_data["externalId"]

    # Store the user
    users[user_id] = new_user

    print(f"DEBUG: SUCCESS - Created user '{new_user['userName']}' with ID {user_id}", file=sys.stderr)
    print(f"DEBUG: User details: displayName={new_user.get('displayName', 'N/A')}, active={new_user.get('active')}", file=sys.stderr)
    print(f"DEBUG: Total users in store: {len(users)}", file=sys.stderr)
    print("="*80, file=sys.stderr)

    return jsonify(new_user), 201

@app.route(f"{SCIM_BASE_URL}/Users/<string:user_id>", methods=['GET', 'PUT'])
def handle_user(user_id):
    """Return or update a specific user by ID."""
    if user_id not in users:
        print(f"DEBUG: User '{user_id}' not found", file=sys.stderr)
        return scim_error(f"User with id '{user_id}' not found.", 404)

    if request.method == 'GET':
        print("="*80, file=sys.stderr)
        print(f"DEBUG: GET /Users/{user_id} - Retrieve User", file=sys.stderr)
        print("="*80, file=sys.stderr)
        user = users[user_id]
        print(f"DEBUG: Returning user: {user['userName']}", file=sys.stderr)
        print("="*80, file=sys.stderr)
        return jsonify(user), 200

    elif request.method == 'PUT':
        print("="*80, file=sys.stderr)
        print(f"DEBUG: PUT /Users/{user_id} - Update User", file=sys.stderr)
        print("="*80, file=sys.stderr)
        user_data = request.get_json(silent=True)
        print(f"DEBUG: Update payload: {user_data}", file=sys.stderr)

        # Update the user with new data from Okta
        from datetime import datetime
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Preserve the ID and created timestamp
        existing_user = users[user_id]
        created_timestamp = existing_user.get("meta", {}).get("created", timestamp)

        # Build updated user object
        updated_user = {
            "schemas": user_data.get("schemas", ["urn:ietf:params:scim:schemas:core:2.0:User"]),
            "id": user_id,  # Preserve existing ID
            "userName": user_data.get("userName", existing_user.get("userName")),
            "active": user_data.get("active", existing_user.get("active", True)),
            "groups": existing_user.get("groups", []),  # RFC 7643: readOnly attribute
            "meta": {
                "resourceType": "User",
                "created": created_timestamp,
                "lastModified": timestamp,
                "location": f"{SCIM_BASE_URL}/Users/{user_id}"
            }
        }

        # Copy optional attributes if provided
        if "name" in user_data:
            updated_user["name"] = user_data["name"]
        if "displayName" in user_data:
            updated_user["displayName"] = user_data["displayName"]
        if "emails" in user_data:
            updated_user["emails"] = user_data["emails"]
        if "externalId" in user_data:
            updated_user["externalId"] = user_data["externalId"]

        # Store the updated user
        users[user_id] = updated_user

        print(f"DEBUG: SUCCESS - Updated user '{updated_user['userName']}'", file=sys.stderr)
        print(f"DEBUG: User details: displayName={updated_user.get('displayName', 'N/A')}, active={updated_user.get('active')}", file=sys.stderr)
        print("="*80, file=sys.stderr)

        return jsonify(updated_user), 200

@app.route(f"{SCIM_BASE_URL}/Schemas", methods=['GET'])
def get_schemas():
    print("DEBUG: Received GET /Schemas request.", file=sys.stderr)
    return jsonify(scim_list_response([USER_SCHEMA, GROUP_SCHEMA])), 200

@app.route(f"{SCIM_BASE_URL}/ResourceTypes", methods=['GET'])
def get_resource_types():
    print("DEBUG: Received GET /ResourceTypes request.", file=sys.stderr)
    return jsonify(scim_list_response([USER_RESOURCETYPE, GROUP_RESOURCETYPE])), 200

@app.route("/version", methods=['GET'])
def get_version():
    """Returns the application build timestamp."""
    build_timestamp = os.environ.get('APP_BUILD_TIMESTAMP', 'UNKNOWN')
    print(f"DEBUG: Received GET /version request. Build timestamp: {build_timestamp}", file=sys.stderr)
    return jsonify({"version": build_timestamp}), 200

# --- SCIM Group Endpoints (with Non-Compliant behaviors) ---

@app.route(f"{SCIM_BASE_URL}/Groups", methods=['GET', 'POST'])
def handle_groups():
    if request.method == 'POST':
        return create_group()
    elif request.method == 'GET':
        return get_groups()

def get_groups():
    filter_query = request.args.get('filter')
    print(f"DEBUG: Received GET /Groups request with filter: {filter_query}", file=sys.stderr)
    
    found_groups = []
    if filter_query and 'displayName eq ' in filter_query:
        try:
            name_to_find = filter_query.split('eq ')[1].strip('"')
            for group in groups.values():
                if group.get('displayName') == name_to_find:
                    found_groups.append(group)
            print(f"DEBUG: Found {len(found_groups)} groups matching displayName '{name_to_find}'", file=sys.stderr)
        except IndexError:
            return scim_error("Invalid filter format", 400)
    else:
        found_groups = list(groups.values())
        print(f"DEBUG: No filter applied, returning all {len(found_groups)} groups.", file=sys.stderr)

    return jsonify(scim_list_response(found_groups)), 200

def create_group():
    print("="*80, file=sys.stderr)
    print("DEBUG: POST /Groups - Create Group Request", file=sys.stderr)
    print("="*80, file=sys.stderr)
    group_data = request.get_json(silent=True)
    print(f"DEBUG: Full request payload: {group_data}", file=sys.stderr)

    if not group_data.get("schemas") or "urn:ietf:params:scim:schemas:core:2.0:Group" not in group_data["schemas"]:
        print("DEBUG: FAILED - Invalid SCIM Group schema", file=sys.stderr)
        return scim_error("Invalid SCIM Group schema.", 400)
    if not group_data.get("displayName"):
        print("DEBUG: FAILED - Missing required attribute 'displayName'", file=sys.stderr)
        return scim_error("Missing required attribute 'displayName'.", 400)

    group_id = str(uuid.uuid4())
    if 'members' not in group_data:
        group_data['members'] = []

    print(f"DEBUG: Group name: '{group_data['displayName']}'", file=sys.stderr)
    print(f"DEBUG: Members in request: {len(group_data.get('members', []))}", file=sys.stderr)

    # --- NON-COMPLIANT BEHAVIOR: Reject groups with members ---
    # This server doesn't maintain user information, so it cannot verify member existence
    # Simulates Snowflake behavior where members can't be added if not in user database
    if group_data.get('members', []):
        print(f"DEBUG: NON-COMPLIANT BEHAVIOR TRIGGERED!", file=sys.stderr)
        print(f"DEBUG: REJECTING group creation because members are present", file=sys.stderr)
        print(f"DEBUG: Attempted members: {group_data.get('members')}", file=sys.stderr)
        print(f"DEBUG: Reason: Server has no user database to verify member existence (Snowflake simulation)", file=sys.stderr)
        return scim_error("Cannot add members: user verification not available.", 400)

    new_group = {
        "id": group_id,
        "displayName": group_data["displayName"],
        "members": group_data["members"],
        "schemas": group_data["schemas"],
        "meta": {"resourceType": "Group", "location": f"{SCIM_BASE_URL}/Groups/{group_id}"}
    }
    groups[group_id] = new_group
    print(f"DEBUG: SUCCESS - Created group '{new_group['displayName']}' with ID {group_id}", file=sys.stderr)
    print(f"DEBUG: Initial members count: {len(new_group['members'])}", file=sys.stderr)
    print(f"DEBUG: Expecting Okta to send PATCH request next to add members (which will FAIL)", file=sys.stderr)
    print("="*80, file=sys.stderr)
    return jsonify(new_group), 201

@app.route(f"{SCIM_BASE_URL}/Groups/<string:group_id>", methods=['GET', 'PATCH', 'DELETE'])
def handle_group(group_id):
    """
    Handles GET, PATCH, and DELETE requests for a specific group.
    """
    if group_id not in groups:
        return scim_error(f"Group with id '{group_id}' not found.", 404)

    if request.method == 'GET':
        print("="*80, file=sys.stderr)
        print(f"DEBUG: GET /Groups/{group_id} - Retrieve Group", file=sys.stderr)
        print("="*80, file=sys.stderr)
        group = groups[group_id]
        print(f"DEBUG: Returning group: '{group.get('displayName')}'", file=sys.stderr)
        print(f"DEBUG: Current members: {len(group.get('members', []))}", file=sys.stderr)
        if group.get('members'):
            print(f"DEBUG: Member details: {group.get('members')}", file=sys.stderr)
        print("="*80, file=sys.stderr)
        return jsonify(group), 200
    
    elif request.method == 'PATCH':
        print("="*80, file=sys.stderr)
        print(f"DEBUG: PATCH /Groups/{group_id} - Update Group Request", file=sys.stderr)
        print("="*80, file=sys.stderr)
        patch_data = request.get_json(silent=True)
        print(f"DEBUG: Full PATCH payload: {patch_data}", file=sys.stderr)

        if not patch_data or "Operations" not in patch_data:
            print("DEBUG: FAILED - Invalid PATCH request format (missing Operations)", file=sys.stderr)
            return scim_error("Invalid PATCH request format.", 400)

        group_to_update = groups[group_id]
        print(f"DEBUG: Current group state: displayName='{group_to_update.get('displayName')}', members={len(group_to_update.get('members', []))}", file=sys.stderr)
        print(f"DEBUG: Processing {len(patch_data['Operations'])} operation(s)...", file=sys.stderr)

        for idx, op in enumerate(patch_data["Operations"]):
            print(f"DEBUG: Operation #{idx+1}: {op}", file=sys.stderr)
            op_type = op.get("op", "").lower()
            path = op.get("path", "")  # Get path for standard ops
            value = op.get("value")
            print(f"DEBUG:   - Type: {op_type}", file=sys.stderr)
            print(f"DEBUG:   - Path: '{path}'", file=sys.stderr)
            print(f"DEBUG:   - Value: {value}", file=sys.stderr)

            # --- Check for operations in the value dict (path-less format) ---
            if op_type == 'replace' and isinstance(value, dict):
                # Check for displayName change (group rename) - NON-COMPLIANT BEHAVIOR #2
                if 'displayName' in value and value['displayName'] != group_to_update.get('displayName'):
                    print(f"DEBUG: NON-COMPLIANT BEHAVIOR TRIGGERED!", file=sys.stderr)
                    print(f"DEBUG: REJECTING group rename attempt (path-less format)", file=sys.stderr)
                    print(f"DEBUG: Old name: '{group_to_update.get('displayName')}'", file=sys.stderr)
                    print(f"DEBUG: New name: '{value['displayName']}'", file=sys.stderr)
                    print(f"DEBUG: Reason: Simulates Microsoft's broken SCIM (groups cannot be renamed)", file=sys.stderr)
                    print("="*80, file=sys.stderr)
                    return scim_error("Group rename is not supported.", 409)

                # Check for member changes - NON-COMPLIANT BEHAVIOR #1
                if 'members' in value:
                    if value.get('members', []):
                        print(f"DEBUG: NON-COMPLIANT BEHAVIOR TRIGGERED!", file=sys.stderr)
                        print(f"DEBUG: REJECTING member addition (path-less replace format)", file=sys.stderr)
                        print(f"DEBUG: Attempted to set {len(value.get('members', []))} member(s)", file=sys.stderr)
                        print(f"DEBUG: Member details: {value.get('members')}", file=sys.stderr)
                        print(f"DEBUG: Reason: Server has no user database to verify member existence (Snowflake simulation)", file=sys.stderr)
                        print("="*80, file=sys.stderr)
                        return scim_error("Cannot add members: user verification not available.", 400)
                    else:
                        # Allow clearing members
                        group_to_update['members'] = []
                        print(f"DEBUG: Cleared members list (setting to empty array)", file=sys.stderr)

                # If we get here, it's just a status update with no actual changes
                if 'members' not in value and ('displayName' not in value or value['displayName'] == group_to_update.get('displayName')):
                    print(f"DEBUG: Replace operation with no meaningful changes", file=sys.stderr)
                    print(f"DEBUG: This appears to be a status check or no-op update from Okta", file=sys.stderr)

            # Handle standard rename with path (from documentation) - NON-COMPLIANT BEHAVIOR #2
            elif op_type == 'replace' and path == 'displayName':
                # Only fail if the displayName is actually changing
                if value != group_to_update.get('displayName'):
                    print(f"DEBUG: NON-COMPLIANT BEHAVIOR TRIGGERED!", file=sys.stderr)
                    print(f"DEBUG: REJECTING group rename attempt (with path format)", file=sys.stderr)
                    print(f"DEBUG: Old name: '{group_to_update.get('displayName')}'", file=sys.stderr)
                    print(f"DEBUG: New name: '{value}'", file=sys.stderr)
                    print(f"DEBUG: Reason: Simulates Microsoft's broken SCIM (groups cannot be renamed)", file=sys.stderr)
                    print("="*80, file=sys.stderr)
                    return scim_error("Group rename is not supported.", 409)

            # Handle member additions via standard 'add' operation with path - NON-COMPLIANT BEHAVIOR #1
            elif op_type == 'add' and path == 'members':
                print(f"DEBUG: NON-COMPLIANT BEHAVIOR TRIGGERED!", file=sys.stderr)
                print(f"DEBUG: REJECTING member addition (add with path format)", file=sys.stderr)
                if isinstance(value, list):
                    print(f"DEBUG: Attempted to add {len(value)} member(s)", file=sys.stderr)
                else:
                    print(f"DEBUG: Attempted to add 1 member", file=sys.stderr)
                print(f"DEBUG: Member details: {value}", file=sys.stderr)
                print(f"DEBUG: Reason: Server has no user database to verify member existence (Snowflake simulation)", file=sys.stderr)
                print("="*80, file=sys.stderr)
                return scim_error("Cannot add members: user verification not available.", 400)

            # Handle member replace via standard 'replace' operation with path='members' - NON-COMPLIANT BEHAVIOR #1
            elif op_type == 'replace' and path == 'members':
                if value and len(value) > 0:
                    print(f"DEBUG: NON-COMPLIANT BEHAVIOR TRIGGERED!", file=sys.stderr)
                    print(f"DEBUG: REJECTING member replace (replace with path='members' format)", file=sys.stderr)
                    print(f"DEBUG: Attempted to set {len(value)} member(s)", file=sys.stderr)
                    print(f"DEBUG: Member details: {value}", file=sys.stderr)
                    print(f"DEBUG: Reason: Server has no user database to verify member existence (Snowflake simulation)", file=sys.stderr)
                    print("="*80, file=sys.stderr)
                    return scim_error("Cannot add members: user verification not available.", 400)
                else:
                    # Allow clearing members with empty array
                    group_to_update['members'] = []
                    print(f"DEBUG: Cleared members list (replace with path='members', empty array)", file=sys.stderr)

            # Handle member removals via standard 'remove' operation with path (from documentation)
            elif op_type == 'remove' and path == 'members':
                # If 'value' is present, it specifies which members to remove
                if value:
                    if not isinstance(value, list):
                        value = [value] # Make it a list for consistent iteration
                    members_to_remove_ids = [m.get('value') for m in value if isinstance(m, dict)]
                    removed_count = len([m for m in group_to_update['members'] if m.get('value') in members_to_remove_ids])
                    group_to_update['members'] = [m for m in group_to_update['members'] if m.get('value') not in members_to_remove_ids]
                    print(f"DEBUG: Removed {removed_count} member(s) from group", file=sys.stderr)
                else: # If no 'value', remove all members
                    removed_count = len(group_to_update['members'])
                    group_to_update['members'] = []
                    print(f"DEBUG: Removed all {removed_count} member(s) from group", file=sys.stderr)

            # If an operation is not handled, log it comprehensively for debugging
            else:
                print(f"DEBUG: UNHANDLED/UNKNOWN OPERATION DETECTED!", file=sys.stderr)
                print(f"DEBUG: This operation doesn't match any of our defined behaviors", file=sys.stderr)
                print(f"DEBUG: Full operation: {op}", file=sys.stderr)
                print(f"DEBUG: Breakdown:", file=sys.stderr)
                print(f"DEBUG:   - Operation type (op): '{op_type}'", file=sys.stderr)
                print(f"DEBUG:   - Path: '{path}'", file=sys.stderr)
                print(f"DEBUG:   - Value type: {type(value).__name__}", file=sys.stderr)
                print(f"DEBUG:   - Value content: {value}", file=sys.stderr)

                # Check if it's a replace operation with unexpected content
                if op_type == 'replace':
                    print(f"DEBUG: This is a REPLACE operation", file=sys.stderr)
                    if isinstance(value, dict):
                        print(f"DEBUG: Value is a dict with keys: {list(value.keys())}", file=sys.stderr)
                    elif isinstance(value, list):
                        print(f"DEBUG: Value is a list with {len(value)} items", file=sys.stderr)
                    else:
                        print(f"DEBUG: Value is a scalar: {value}", file=sys.stderr)

                print(f"DEBUG: Returning 400 error for unsupported operation", file=sys.stderr)
                print("="*80, file=sys.stderr)
                return scim_error(f"Unsupported PATCH operation: {op}", 400)

        groups[group_id] = group_to_update
        print(f"DEBUG: SUCCESS - All PATCH operations completed", file=sys.stderr)
        print(f"DEBUG: Final group state: displayName='{group_to_update.get('displayName')}', members={len(group_to_update.get('members', []))}", file=sys.stderr)
        print("="*80, file=sys.stderr)
        return jsonify(group_to_update), 200

    elif request.method == 'DELETE':
        print("="*80, file=sys.stderr)
        print(f"DEBUG: DELETE /Groups/{group_id} - Delete Group", file=sys.stderr)
        print("="*80, file=sys.stderr)
        group = groups[group_id]
        print(f"DEBUG: Deleting group: '{group.get('displayName')}'", file=sys.stderr)
        print(f"DEBUG: Group had {len(group.get('members', []))} member(s)", file=sys.stderr)
        groups.pop(group_id)
        print(f"DEBUG: SUCCESS - Group deleted", file=sys.stderr)
        print("="*80, file=sys.stderr)
        return '', 204


if __name__ == '__main__':
    print("\n" + "="*80, file=sys.stderr, flush=True)
    print("NON-COMPLIANT SCIM SERVER STARTING", file=sys.stderr, flush=True)
    print("="*80, file=sys.stderr, flush=True)
    print("This server simulates two types of broken SCIM behavior:", file=sys.stderr, flush=True)
    print("", file=sys.stderr, flush=True)
    print("USER PROVISIONING:", file=sys.stderr, flush=True)
    print("  - User store starts EMPTY", file=sys.stderr, flush=True)
    print("  - Accepts ANY users pushed from Okta via POST /Users or PUT /Users/{id}", file=sys.stderr, flush=True)
    print("  - Okta can provision users dynamically with any email/username", file=sys.stderr, flush=True)
    print("  - Once users are provisioned, Okta will attempt group membership operations", file=sys.stderr, flush=True)
    print("", file=sys.stderr, flush=True)
    print("1. SNOWFLAKE BEHAVIOR: Cannot add members to groups", file=sys.stderr, flush=True)
    print("   - Groups must be created with empty members (SUCCESS)", file=sys.stderr, flush=True)
    print("   - Any PATCH to add members will FAIL with 400", file=sys.stderr, flush=True)
    print("   - Reason: Simulates systems that can't verify member existence", file=sys.stderr, flush=True)
    print("", file=sys.stderr, flush=True)
    print("2. MICROSOFT BEHAVIOR: Cannot rename groups", file=sys.stderr, flush=True)
    print("   - Any PATCH to change displayName will FAIL with 409", file=sys.stderr, flush=True)
    print("   - Reason: Group renames are not supported", file=sys.stderr, flush=True)
    print("", file=sys.stderr, flush=True)
    print("Expected Okta workflow:", file=sys.stderr, flush=True)
    print("  Step 1: POST /Users -> Provision users (SUCCESS - 201)", file=sys.stderr, flush=True)
    print("  Step 2: GET /Users -> Okta verifies users exist (SUCCESS - 200)", file=sys.stderr, flush=True)
    print("  Step 3: POST /Groups with empty members -> SUCCESS (201)", file=sys.stderr, flush=True)
    print("  Step 4: PATCH /Groups/{id} to add members -> FAILURE (400) <-- NON-COMPLIANT!", file=sys.stderr, flush=True)
    print("="*80 + "\n", file=sys.stderr, flush=True)
    app.run(debug=True, port=5000, host='0.0.0.0')
