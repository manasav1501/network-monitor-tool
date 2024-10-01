import socket
import struct
from flask import Flask, render_template_string, request
from datetime import datetime

app = Flask(__name__)

# Global list to store captured traffic
captured_traffic = []
is_paid = False  # Initialize the 'is_paid' state to False

def monitor_traffic():
    # Create a raw socket to capture IP packets
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # Use AF_PACKET for Linux
    sock.bind(('eth0', 0))  # Bind to the interface, replace 'eth0' with your active interface

    print("Monitoring traffic...")  # Debugging line

    # Capture packets
    while True:
        packet = sock.recvfrom(65565)[0]  # Receive packet
        ip_header = packet[14:34]  # Extract IP header (assuming Ethernet frame)
        ip_src, ip_dst = struct.unpack('!4s4s', ip_header[12:20])  # Unpack source and destination IPs
        ip_src = socket.inet_ntoa(ip_src)  # Convert to human-readable format
        ip_dst = socket.inet_ntoa(ip_dst)

        # Log the traffic
        log_traffic(ip_src, ip_dst)

def log_traffic(ip_src, ip_dst):
    # Get the current time
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    status = "Normal"  # Default to normal traffic

    # Append new traffic data to the global list
    captured_traffic.append((ip_src, ip_dst, timestamp, status))

    # Debugging line to show captured traffic
    print(f"Captured: {ip_src} -> {ip_dst} at {timestamp}")

def filter_traffic(search_query):
    # If there's no search query, return all traffic
    if not search_query:
        return captured_traffic

    # Initialize an empty list for filtered traffic
    filtered = []

    # Split the query to find the search field and value
    search_query = search_query.strip().lower()

    # Parse for "Source IP", "Destination IP", "Time", or "Status"
    for entry in captured_traffic:
        ip_src, ip_dst, timestamp, status = entry
        if "source ip:" in search_query:
            if search_query.split(":")[1].strip() in ip_src.lower():
                filtered.append(entry)
        elif "destination ip:" in search_query:
            if search_query.split(":")[1].strip() in ip_dst.lower():
                filtered.append(entry)
        elif "time:" in search_query:
            if search_query.split(":")[1].strip() in timestamp.lower():
                filtered.append(entry)
        elif "status:" in search_query:
            if search_query.split(":")[1].strip() in status.lower():
                filtered.append(entry)

    # Return the filtered traffic
    return filtered

@app.route('/', methods=['GET', 'POST'])
def index():
    global is_paid

    # Check if the "Pay Now" button was clicked
    if request.method == 'POST' and 'pay' in request.form:
        is_paid = True  # Set the 'is_paid' flag to True when payment is made

    # Get search query from the form if it's a POST request
    search_query = request.form.get('search') if request.method == 'POST' else None

    # Filter the traffic based on the search query (if any)
    filtered_traffic = filter_traffic(search_query)

    # HTML with updated search bar and display logic
    html = """
    <html>
        <head>
            <style>
                body {
                    background-color: #162B02;
                    color: #fff2cc;
                    font-family: Arial, sans-serif;
                }
                h1, h2 {
                    font-family: 'Playfair Display SC', serif;
                    text-align: center;
                }
                h1 {
                    font-size: 3em;
                }
                h2 {
                    font-size: 2em;
                }
                table {
                    margin: auto;
                    border-collapse: collapse;
                    width: 80%;
                    font-size: 1.2em;
                    border: 1px solid #fff2cc; /* Outline for the table */
                }
                th, td {
                    border: 1px solid #fff2cc; /* Outline for each cell */
                    text-align: center;
                    padding: 8px;
                    height: 40px;
                    color: #fff2cc; /* Cream white text for table data */
                }
                th {
                    background-color: #fff2cc; /* Cream white for headings */
                    color: #162B02; /* Dark olive green font for headings */
                }
                .search-container {
                    text-align: center;
                    margin-bottom: 20px;
                }
                .search-bar {
                    width: 80%;
                    padding: 8px;
                    border: 2px solid #fff2cc;
                    border-radius: 4px;
                    background-color: #162B02;
                    color: #fff2cc;
                }
                .search-bar::placeholder {
                    color: #fff2cc;
                }
                .search-button {
                    background-color: #fff2cc;
                    border: none;
                    color: #162B02;
                    font-size: 16px;
                    padding: 8px;
                    cursor: pointer;
                }
            </style>
        </head>
        <body>
            <h1>IP Monitoring</h1>
            <h2>Captured Traffic</h2>

            <div class="search-container">
                <form method="POST">
                    <input type="text" name="search" class="search-bar" placeholder="Search by Source IP, Destination IP, Time, Status...">
                    <button type="submit" class="search-button">🔍</button>
                </form>
            </div>

            <table>
                <tr>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Time</th>
                    <th>Status</th>
                </tr>
    """

    # Display filtered traffic
    for i, (ip_src, ip_dst, timestamp, status) in enumerate(filtered_traffic):
        # Display up to 5 rows or all rows if paid
        if i >= 5 and not is_paid:
            break
        html += f"""
                <tr>
                    <td>{ip_src}</td>
                    <td>{ip_dst}</td>
                    <td>{timestamp}</td>
                    <td>{status}</td>
                </tr>
        """

    html += """
            </table>
            <br>
            <div style="text-align: center;">
                <form method="POST">
                    <button type="submit" name="pay" class="search-button" style="width: 150px;">Pay Now</button>
                </form>
            </div>
        </body>
    </html>
    """

    return render_template_string(html)

if __name__ == "__main__":
    # Start monitoring traffic in a separate thread
    import threading
    traffic_thread = threading.Thread(target=monitor_traffic, daemon=True)
    traffic_thread.start()

    # Start the web server
    app.run(host='127.0.0.1', port=5000)
