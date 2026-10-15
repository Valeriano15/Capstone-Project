import os
import platform
import urllib.request
import urllib.error
import json
from fastmcp import FastMCP

# Initialize the MCP Server
mcp = FastMCP("My Full Tool Server")

@mcp.tool
def get_system_info() -> str:
    """Retrieve basic system information and OS details."""
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "current_directory": os.getcwd()
    }
    return json.dumps(info, indent=2)

@mcp.tool
def fetch_url(url: str) -> str:
    """Fetch the text content of a URL. Useful for reading web pages or APIs."""
    try:
        # Add a user-agent to prevent basic bot blocking
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (MCP-Agent; +http://example.com)'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read().decode('utf-8')
            # Truncate to the first 5000 characters to prevent overwhelming the AI's context window
            if len(html) > 5000:
                return html[:5000] + "\n...[CONTENT TRUNCATED]..."
            return html
    except urllib.error.URLError as e:
        return f"Failed to fetch URL: {e.reason}"
    except Exception as e:
         return f"An error occurred: {str(e)}"

@mcp.tool
def list_files(directory: str = ".") -> list[str]:
    """List all files and folders in the specified directory."""
    try:
        target_path = os.path.abspath(directory)
        if not os.path.exists(target_path):
            return [f"Error: Directory '{directory}' does not exist."]
        return os.listdir(target_path)
    except PermissionError:
        return ["Error: Permission denied."]
    except Exception as e:
        return [f"Error reading directory: {str(e)}"]

@mcp.tool
def read_file(filepath: str) -> str:
    """Read the contents of a specific text file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            # Truncate if the file is massive
            if len(content) > 10000:
                return content[:10000] + "\n...[TRUNCATED]"
            return content
    except FileNotFoundError:
        return "Error: File not found."
    except UnicodeDecodeError:
        return "Error: File appears to be a binary, not a readable text file."
    except Exception as e:
        return f"Error reading file: {str(e)}"

if __name__ == "__main__":
    # Starts the server using standard input/output (stdio)
    mcp.run()