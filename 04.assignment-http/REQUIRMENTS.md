# Requirements
---

## Requirements for HTTP Server Implementation

### **Objective**
Develop a fully functional HTTP server that:
- Serves a sample website with multiple resources (HTML, CSS, JavaScript, images).
- Handles specific HTTP GET requests for calculations.
- Implements proper HTTP error codes and resource handling.

---

### **Requirements**

#### 1. **Serve a Website**
   - **Description**:
     - The server must host the contents of the provided `webroot.zip` directory.
     - Clients accessing `http://127.0.0.1:80` should see the `index.html` file, along with all linked resources.
   - **Solution Hint**:
     - Use Python's `os` module to navigate the directory structure and locate files.
     - Read the requested file and return its contents with appropriate HTTP headers.
     - Default to `index.html` if no specific resource is requested.

#### 2. **HTTP Error Codes**
   - **Required Codes**:
     1. **200 OK**: Successful request, content is returned.
     2. **302 Moved Temporarily**: Redirect to another resource (e.g., `/calculate-next`).
     3. **404 Not Found**: Requested resource does not exist.
   - **Solution Hint**:
     - Implement a dictionary of valid routes.
     - Check the requested path and return the corresponding HTTP code and message.

#### 3. **GET Request: `calculate-next`**
   - **Description**:
     - Process requests like `http://127.0.0.1:80/calculate-next?num=16`.
     - Return the next number (`17` for the above example).
   - **Solution Hint**:
     - Parse the query string using Python's `urllib.parse` module.
     - Extract the `num` parameter and compute the result.

#### 4. **GET Request: `calculate-area`**
   - **Description**:
     - Process requests like `http://127.0.0.1:80/calculate-area?height=3&width=4`.
     - Return the area (`12` for the above example).
   - **Solution Hint**:
     - Extract `height` and `width` from the query string.
     - Calculate the area as `height * width` and return the result.

#### 5. **Default Resource Handling**
   - **Description**:
     - If no resource is specified, serve `index.html` as the default.
   - **Solution Hint**:
     - Check for empty or `/` paths and map them to `index.html`.

#### 6. **Handle Resource Not Found (404)**
   - **Description**:
     - If the requested file or resource does not exist, return a `404` error.
   - **Solution Hint**:
     - Use Python's `os.path.exists` to verify the file's presence before serving.

#### 7. **Handle Client Disconnections**
   - **Description**:
     - Ensure the server remains functional after a client disconnects.
   - **Solution Hint**:
     - Use exception handling (`try/except`) around socket operations to gracefully close connections.

#### 8. **Favicon Handling**
   - **Description**:
     - Serve the `favicon.ico` file for browsers that request it.
   - **Solution Hint**:
     - Add a specific route for `/favicon.ico` to serve the file from `webroot`.

---

### **Grading Criteria**
- The server properly serves all parts of the website, including linked resources (60 points).
- Correct implementation of `302` (20 points) and `404` (20 points).
- Working `calculate-area` functionality for valid inputs (20 points).
- Proper validation of HTTP requests and responses (20 points).
- Default resource handling (20 points).
- Robustness: Server remains operational after client disconnects (20 points).
