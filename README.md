# TOL103M - Assignment P3  
Lownet Security: AES Encryption and Signed Packets  

Course: TÖL103M – Fall 2025  
Instructors: Hyytiä and Ágústsson  

Description  
This assignment aims to enhance the Lownet networking stack by incorporating advanced security features.  

Implemented Features  

Milestone I  
- Integration of AES-256 encryption in Cipher Block Chaining (CBC) mode.  
- Development of Encrypted Packet Format version 2.  
- Activation of runtime encryption key configuration through the serial console.  
- Introduction of the `/testenc` command for the purpose of encryption verification.  

Milestone II  
- Implementation of RSA along with SHA-256 digital signature verification.  
- Support for multi-frame signed packets.  
- Establishment of a secure command protocol that incorporates sequence numbers.  
- Execution of secure time updates via signed commands.  

Notes  
- Insecure Packet Format version 1 is disregarded when encryption is activated.  
- Only commands that are both signed and validated will be accepted.  
