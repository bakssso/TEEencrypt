#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define RSA_KEY_LEN 1024
#define RSA_PLAIN_LEN 86 // 1024/8 - 42 (padding)
#define RSA_CIPHER_LEN (RSA_KEY_LEN/8)

#define CAESAR_PLAIN_LEN 64 

void write_file(char *name, char *text, int key) {
	FILE *f = fopen(name, "w+");
	fwrite(text, strlen(text), 1, f);
	if (key != 0){
		fprintf(f, "%d", key);
	}
	fclose(f);	
}

int main(int argc, char *argv[])
{
	TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_TEEencrypt_UUID;
    uint32_t err_origin;
	// base set

	char plaintext[CAESAR_PLAIN_LEN];
	char ciphertext[CAESAR_PLAIN_LEN];
	char caesar_key[CAESAR_PLAIN_LEN];
	// ~ caesar encryption

	char plain[RSA_PLAIN_LEN];
	char cipher[RSA_CIPHER_LEN];
	// ~ RSA encryption

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	memset(&op, 0, sizeof(op));
	// init 

	// TEEencrypt argv[1] argv[2] caesar
	if (!strcmp(argv[3], "caesar")){
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
						TEEC_NONE, TEEC_NONE);
		
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = CAESAR_PLAIN_LEN;
		op.params[1].value.a = 0;

		// TEEencrypt -e @input caesar
		// 	@input  : textfile
		// 	@output : caesarCipher.txt
		//				- encrypted text + \n + encrypt key
		if (!strcmp(argv[1], "-e")){
			printf("caesar encryption\n");
			// Read file to encrypt	
			FILE *pf = fopen(argv[2], "r");
			if (pf == NULL){
				printf("%s : not found\n", argv[2]);
				return 1;	
			}
			fgets(plaintext, sizeof(plaintext), pf);
			fclose(pf);
			// Copy plaintext to op's share memory
			memcpy(op.params[0].tmpref.buffer, plaintext, CAESAR_PLAIN_LEN); 
			
			// Invoke TA's caesar encrypt service
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
					
			// Copy ta's return value to ciphertext
			memcpy(ciphertext, op.params[0].tmpref.buffer, CAESAR_PLAIN_LEN);
			// Print result
			printf("Encrypted text : %s\n", ciphertext);
			printf("key : %d\n", op.params[1].value.a);
			// Write ciphertext&key to txt file
			write_file("caesarCipher.txt", plaintext, op.params[1].value.a);
		} 
		// TEEencrypt -d @input caesar
		// 	@input  : caesarCipher.txt
		// 	@output : caesarPlain.txt
		//		caesarPlain must be equal to original txt.
		else if (!strcmp(argv[1],"-d")){
			printf("Caesar decryption\n");
			// Read file to decrypt
			FILE *ef = fopen(argv[2], "r");
			if (ef == NULL){
				printf("%s : not found\n", argv[2]);
				return 1;
			}
			fgets(ciphertext, sizeof(ciphertext), ef);
			fgets(caesar_key, sizeof(caesar_key), ef);
			// Get ciphertext & key
			fclose(ef);
			// Close file pointer

			// Copy ciphertext to op's share memory
			memcpy(op.params[0].tmpref.buffer, ciphertext, CAESAR_PLAIN_LEN);
			int key = atoi(caesar_key);
			op.params[1].value.a = key;

			// Invoke TA's caesar decryption service
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
			
			// Copy ta's return value to ciphertext
			memcpy(plaintext, op.params[0].tmpref.buffer, CAESAR_PLAIN_LEN);
			printf("Decrypted text : %s\n", plaintext);
			printf("Key : %d\n", op.params[1].value.a);
			write_file("caesarPlain.txt", plaintext, 0);
		}else{ // Exception for invalid argument
			printf("Invalid argument %s\n", argv[2]);
			return 1;
		}
	// TEEencrypt argv[1] argv[2] RSA
	}else if (!strcmp(argv[3],"RSA")){		
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
								TEEC_MEMREF_TEMP_OUTPUT,
								TEEC_NONE, TEEC_NONE);
	
		op.params[0].tmpref.buffer = plain;
		op.params[0].tmpref.size = RSA_PLAIN_LEN;
		op.params[1].tmpref.buffer = cipher;
		op.params[1].tmpref.size = RSA_CIPHER_LEN;
		// Invoke GEN RSA KEYS
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_CMD_GENKEYS, NULL, NULL);
		if (res != TEEC_SUCCESS)
			errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
		printf("\n=========== Keys already generated. ==========\n");
		// TEEencrypt -e @input RSA
		// @input  : textfile
		// @output : rsaCipher.txt , rsaPlain.txt
		//        rsaPlain must be equal to texfile
		if (!strcmp(argv[1],"-e")){
			printf("RSA encryption\n");
			// Read file to encrypt	
			FILE *pf = fopen(argv[2], "r");
			if (pf == NULL){
				printf("%s : not found\n", argv[2]);
				return 1;	
			}
			fgets(plain, sizeof(plain), pf);
			fclose(pf);
			// enc
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_CMD_ENC_VALUE,
				 &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_RSA_CMD_ENC_VALUE) failed 0x%x origin 0x%x\n",
					res, err_origin);
			printf("\nThe hex sent was encrypted: %x\n", cipher);
			write_file("rsaCipher.txt", cipher, 0);
			
			// clear plain for check decryption function
			plain[0] = '\0'; 
			//dec
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_CMD_DEC_VALUE,
									 &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_RSA_CMD_DEC_VALUE) failed 0x%x origin 0x%x\n",
					res, err_origin);
			printf("\nThe text sent was decrypted: %s\n", plain);
			write_file("rsaPlain.txt", plain, 0);
		}
	}else { // Exception for invalid argument
		printf("Invalid argument %s\n", argv[1]);
		return 1;
	}
	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
