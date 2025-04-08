import sys
from collections import namedtuple

# Import the DNSResolver class from your code
# Assuming the code you provided is saved in a file named dns_resolver.py
try:
    from dns_resolver import DNSResolver
except ImportError:
    print("Error: Could not import DNSResolver class")
    sys.exit(1)

def main():
    # List of domains to query
    domains = ["google.com", "wikipedia.com", "github.com"]
    
    # Create a resolver instance
    resolver = DNSResolver()  # Remove the debug parameter from the constructor
    resolver.debug = True     # Set debug attribute directly
    
    try:
        print("DNS Resolution Results:")
        print("-" * 50)
        
        # Resolve each domain
        for domain in domains:
            print(f"\nResolving {domain}...")
            result = resolver.resolve(domain)
            
            if result:
                print(f"✓ Successfully resolved {domain}:")
                for domain_name, ttl, ip in result:
                    print(f"  - {domain_name} -> {ip} (TTL: {ttl}s)")
            else:
                print(f"✗ Failed to resolve {domain}")
    
    finally:
        # Clean up resources
        resolver.close()
        print("\nDNS resolver closed")

if __name__ == "__main__":
    main()