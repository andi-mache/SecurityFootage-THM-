"""
this script processes a PCAP file containing MJPEG streams,it extracts JPEG frames from the TCP payloads,
it uses Scapy to read the PCAP file, extracts frames based on MJPEG boundaries,which are identified by a specific boundary string,
and saves them as JPEG files.
"""

# the os library is used to handle file paths and create directories,
import os

# the re library is used for regular expression matching to find the Content-Length header in the MJPEG stream,
import re

# the subprocess library is used to call FFmpeg for video creation from the extracted JPEG frames,
import subprocess

# the scapy library is used to read the PCAP file and extract TCP payloads,
from scapy.layers.http import HTTP
from scapy.layers.inet import IP
from scapy.all import rdpcap, TCP, Raw


"""
the process_pcap function reads a PCAP file, extracts TCP payloads, and processes them to extract MJPEG frames.
bytes from the TCP payloads are collected, and the extract_frames_from_buffer function is called to handle the MJPEG stream.
"""


def process_pcap(pcap_file):
    print("Reading PCAP file...")
    # the rdpcap function reads the PCAP file and returns a list of packets,
    packets = rdpcap(pcap_file)
    # the bytearray is used to collect TCP payload data
    tcp_data = bytearray()

    # the for loop iterates through each packet in the PCAP file,and checks if the packet has a TCP layer and a Raw layer,
    for packet in packets:
        # Check if packet has TCP layer and payload, then extract the TCP payload,
        # this is done to ensure that only packets containing TCP data are processed,
        # this is where the MJPEG stream is expected to be found,
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            # here the bytes of the TCP payload are extracted and appended to the tcp_data bytearray,
            # the packet[Raw].load contains the raw data of the TCP payload,the .extends method appends this data to the tcp_data bytearray,
            tcp_payload = bytes(packet[Raw].load)
            tcp_data.extend(tcp_payload)

    print("Finished reading PCAP. Processing MJPEG stream...")
    extract_frames_from_buffer(tcp_data)


"""
the extract_frames_from_buffer function processes the collected TCP payload data,by searching for MJPEG boundaries.
The MJPEG boundaries are defined by a specific string (in this case, "--BoundaryString"),
"""


def extract_frames_from_buffer(buffer):
    boundary = b"--BoundaryString"
    frame_count = 0
    offset = 0
    # the while loop iterates through the buffer to find occurrences of the MJPEG boundary string,
    while True:
        offset = buffer.find(boundary, offset)
        if offset == -1:
            break
        # here if the boundary is found, it searches for the next occurrence of the boundary string,and extracts the data between the boundaries,
        # then it looks for the Content-Length header to determine the size of the JPEG frame,
        next_boundary = buffer.find(boundary, offset + len(boundary))
        if next_boundary == -1:
            break

        part = buffer[offset:next_boundary]

        # Find Content-Length by using a regular expression,to match the Content-Length header in the MJPEG stream,
        content_length_match = re.search(
            rb"Content-Length:\s*(\d+)", part, re.IGNORECASE
        )
        if not content_length_match:
            offset = next_boundary
            continue

        content_length = int(content_length_match.group(1))

        # Find end of headers by looking for the double CRLF sequence,to identify the end of the HTTP headers in the MJPEG stream,
        header_end = part.find(b"\r\n\r\n")
        if header_end == -1:
            offset = next_boundary
            continue
        # the jpeg_start is calculated by adding the offset, the length of the boundary, and the length of the headers,
        # and the jpeg_end is calculated by adding the jpeg_start and the content_length,
        jpeg_start = offset + header_end + 4  # the 4 accounts for the \r\n\r\n sequence
        jpeg_end = jpeg_start + content_length

        # we check if the jpeg_end is within the bounds of the buffer,if not, it breaks the loop,
        if jpeg_end > len(buffer):
            break

        jpeg_data = buffer[jpeg_start:jpeg_end]

        # the extracted JPEG data is saved to a file,using the frame_count to create a unique filename for each frame,
        # the frame_count:04d formats the frame number to be four digits long,ensuring consistent naming,
        filename = os.path.join(os.getcwd(), f"frame_{frame_count:04d}.jpg")
        with open(filename, "wb") as f:
            f.write(jpeg_data)
        print(f"Saved frame {frame_count}")
        frame_count += 1

        offset = next_boundary

    print(f"Extraction complete: {frame_count} frames saved.")
    create_video_from_frames()

    """
    the create_video_from_frames function uses FFmpeg to create a video from the extracted JPEG frames.
    it constructs a command to call FFmpeg with the appropriate parameters,
    """


def create_video_from_frames():
    fps = 10  # Change FPS to match your stream's real rate
    output_file = "output_video.mp4"

    cmd = [
        "ffmpeg",
        "-y",  # this parameter helps to overwrite the output file if it already exists,
        "-framerate",
        str(fps),
        "-i",
        "frame_%04d.jpg",
        "-c:v",
        "libx264",  # this specifies the video codec to use,in this case, libx264 is used for H.264 encoding,
        "-pix_fmt",
        "yuv420p",  # this specifies the pixel format for the output video,
        output_file,
    ]

    try:
        subprocess.run(cmd, check=True)
        print(f"🎞️ Video created successfully: {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"❌ FFmpeg error: {e}")


if __name__ == "__main__":
    pcap_file = "security-footage-1648933966395.pcap"
    process_pcap(pcap_file)
