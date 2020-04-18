# PyNet Intelligence - Policy and Disclaimer

Like many cybersecurity tools, it is extremely important to understand the risks of the actions you are performing while using the tools.  Below, I discuss some of the possible implications of using PyNet Intelligence.

### Disclaimer

Running PyNet Intelligence on an IP address in which you are unautherized to use is illegal. PyNet was built for penetration testing on networks in which the owner has specifically contracted the user to test.  

Another possible use case of PyNet is for *learning* about penetration testing. In order to do this without breaking the law, one can use a virtual machine running their own server.  A great service to use for this purpose is [Metasploitable](https://information.rapid7.com/download-metasploitable-2017.html) by Rapid7. This 'intentionally vulnerable server' was used to test many of the functions found in PyNet.

### Policy

The specific law that makes running PyNet on an unauthorized server is Computer Misuse Act of 1990.  This policy states that makes unauthorized use of computer systems a crime.  This law is so specific that even making a GET request to a website is illegal if the owner doesn't want you to.  With that being said, mostly every website want's users to make GET requests because that means that users are indeed visiting their site.

### Another Note

Many of the scans run by PyNet Intelligence will return either Vulnerable or Not Vulnerable.  While this may seem trivial, it is not.  It is hard to completely tell if a system is vulnerable or not to a specific attack in a short period of time. As a result we like to heir on the side of caution and call a server vulnerable if we found a small vulnerability regarding a certain scan.  If a test returns Vulnerable, there is definitley something insecure about the thing we tested, but we are never 100% sure the vulnerability can be exploited.