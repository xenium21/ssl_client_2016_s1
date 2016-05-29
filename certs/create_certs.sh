#!/bin/bash

openssl x509 -x509toreq -in A.pem -out A.csr -signkey AKey.pem

openssl x509 -x509toreq -in B.pem -out B.csr -signkey BKey.pem

openssl x509 -x509toreq -in C.pem -out C.csr -signkey CKey.pem

openssl x509 -req -days 365 -in B.csr -CA A.pem -CAkey AKey.pem -CAcreateserial -out AB.pem

openssl x509 -req -days 365 -in C.csr -CA A.pem -CAkey AKey.pem -CAcreateserial -out AC.pem

openssl x509 -req -days 365 -in A.csr -CA B.pem -CAkey BKey.pem -CAcreateserial -out BA.pem

openssl x509 -req -days 365 -in C.csr -CA B.pem -CAkey BKey.pem -CAcreateserial -out BC.pem

openssl x509 -req -days 365 -in A.csr -CA C.pem -CAkey CKey.pem -CAcreateserial -out CA.pem

openssl x509 -req -days 365 -in B.csr -CA C.pem -CAkey CKey.pem -CAcreateserial -out CB.pem
