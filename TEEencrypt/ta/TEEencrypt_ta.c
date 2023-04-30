#include <stdio.h>
#include <string.h>
// will remove

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <TEEencrypt_ta.h>
#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)
#define rootkey 13
/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
struct rsa_session {
	TEE_OperationHandle op_handle;	/* RSA operation */
	TEE_ObjectHandle key_handle; /* Key handle */
};
TEE_Result check_params(uint32_t param_types, char *type) {

	// rsa param type
	// plain | cipher | none | none
	const uint32_t rsa_exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	// caesar param type
	// text | key | none | none
	const uint32_t caesar_exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_VALUE_INOUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	/* Safely get the invocation parameters */
	if (!strcmp(type, "caesar")){
		if(param_types != caesar_exp_param_types) return TEE_ERROR_BAD_PARAMETERS;
	}
	else{ 
		if (param_types != rsa_exp_param_types) return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void  **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */

	// Set for rsa ( key_handle, op_handle )
	struct rsa_session *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*sess_ctx = (void *)sess;
	DMSG("\nSession %p: newly allocated\n", *sess_ctx);
	IMSG("Hello World!\n");
	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	struct rsa_session *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", sess_ctx);
	sess = (struct rsa_session *)sess_ctx;

	/* Release the session resources
	   These tests are mandatories to avoid PANIC TA (TEE_HANDLE_NULL) */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
	IMSG("Goodbye!\n");
}

void caesarProcess(char *string, int len, int key, bool enc){
	for(int i=0; i<len;i++){
      	if(string[i]>='a' && string[i] <='z'){
			string[i] -= 'a';
			if (enc) string[i] += key;
			else{
				string[i] -= key;
				string[i] += 26;
			}
			string[i] = string[i] % 26;
         	string[i] += 'a';
      	}
     	else if (string[i] >= 'A' && string[i] <= 'Z') {
         	string[i] -= 'A';
         	if (enc) string[i] += key;
			else{
				string[i] -= key;
				string[i] += 26;
			}
         	string[i] = string[i] % 26;
         	string[i] += 'A';
      	}
    }
}
static TEE_Result enc_value(uint32_t param_types,
        TEE_Param params[4])
{
	if (check_params(param_types, "caesar") != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;
	// values 	
	char * plain = (char *)params[0].memref.buffer;
	int len = strlen (params[0].memref.buffer);
	char encrypted[64]={0,};
	unsigned int caesarKey = params[1].value.a;

	// create caesarKey until not zero.
	while (caesarKey == 0){
		TEE_GenerateRandom(&caesarKey, sizeof(caesarKey));		
		caesarKey = caesarKey % 26;
	}
	DMSG("Caesar key : %d", caesarKey);
	DMSG("Plain : %s", plain);
	memcpy(encrypted, plain, len);

	// caesar encryption process
	caesarProcess(encrypted, len, caesarKey, true);

	
	// encrypt rand key with rootkey ( defined 13 )
	unsigned int encrypted_caesarKey = caesarKey * rootkey;	
	DMSG("Encrypted key : %d", encrypted_caesarKey);
	params[1].value.a = encrypted_caesarKey;
	// memcopy encrypted, encrypted_key
	DMSG("Cipher : %s", encrypted);
	memcpy(plain, encrypted, len);
	return TEE_SUCCESS;
}
static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	if (check_params(param_types, "caesar") != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;
	// values
	char * encrypted = (char *)params[0].memref.buffer;
	int encrypted_len = strlen(params[0].memref.buffer);		
	int encrypted_key = params[1].value.a;
	char decrypted[64] = {0,};
	
	// decrypt encrypted_key with rootkey ( defined 17 )
	int decrypt_key = encrypted_key / rootkey;
	DMSG("Decrypt key : %d", decrypt_key);
	
	// decrypt encrypted
	DMSG("Cipher : %s", encrypted); 
	memcpy(decrypted, encrypted, encrypted_len);
	
	// caesar decryption process
	caesarProcess(decrypted, encrypted_len, decrypt_key, false);

	// memcopy decrypted, decrypted key
	DMSG("Plain : %s", decrypted);
	memcpy(encrypted, decrypted, encrypted_len);
	// share randkey for debug. In production must be removed.
	params[1].value.a = decrypt_key;

	return TEE_SUCCESS;
}

static TEE_Result gen_rsa_key(void *session){
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)session;
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	// generate key at session's key_handle.
	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Keys generated. ==========\n");
	return ret;
}

TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_Result ret = TEE_SUCCESS;	
	TEE_ObjectInfo key_info;
	// Set key( generated at gen_rsa_key func ) to key_info
	ret = TEE_GetObjectInfo1(key, &key_info);
	if (ret != TEE_SUCCESS) {
		EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, ret);
		return ret;
	}
	// Allocate algorithm, end/dec mode, keysize to operation handler
	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation allocated successfully. ==========\n");
	// Set key to operation handler
	ret = TEE_SetOperationKey(*handle, key);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key : 0x%x\n", ret);
		return ret;
	}
    DMSG("\n========== Operation key already set. ==========\n");

	return ret;
}

TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types, "RSA") != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to encrypt: %s\n", (char *) plain_txt);
	// Use TEE API
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
					plain_txt, plain_len, cipher, &cipher_len);					
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nEncrypted data: %s\n", (char *) cipher);
	DMSG("\n========== Encryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	// free
	return ret;
}

TEE_Result RSA_decrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types, "RSA") != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing decryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_DECRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to decrypt: %s\n", (char *) cipher);
	ret = TEE_AsymmetricDecrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
				cipher, cipher_len, plain_txt, &plain_len);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to decrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nDecrypted data: %s\n", (char *) plain_txt);
	DMSG("\n========== Decryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeTransientObject(sess->key_handle);
	return ret;
}
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	// (void)&sess_ctx; /* Unused parameter */
	DMSG("INVOKE IN !");
	switch (cmd_id)
	{
	// Caesar
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	// RSA
	case TA_TEEencrypt_RSA_CMD_GENKEYS:
		return gen_rsa_key(sess_ctx);
	case TA_TEEencrypt_RSA_CMD_ENC_VALUE:
		return RSA_encrypt(sess_ctx, param_types, params);
	case TA_TEEencrypt_RSA_CMD_DEC_VALUE:
		return RSA_decrypt(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
