from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization


print("huh")
parameters = dh.generate_parameters(generator=2, key_size=2048)
print("generated")
pem_parameters = parameters.parameter_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.ParameterFormat.PKCS3
)

# Print the PEM-formatted parameters
print(pem_parameters.decode('utf-8'))