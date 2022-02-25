/**
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "concurrent.h"
#include "key.h"
#include "cipher.h"
#include "pthread.h"

struct Vendor128Args {
	SEC_OBJECTID id;

	Sec_Result res;
};

void *concurrent_vendor128(void *arg)
{
	Vendor128Args *args = (Vendor128Args *) arg;

	args->res = testKeyDeriveKeyLadderAes128(
			args->id,
			SEC_KEYTYPE_AES_128,
			SEC_STORAGELOC_RAM,
			SEC_KEYLADDERROOT_UNIQUE,
			SEC_TRUE);

	return NULL;
}

Sec_Result testConcurrentVendor128(SEC_SIZE numThreads) {

	std::vector<pthread_t> threads;
	std::vector<Vendor128Args> args;
	threads.resize(numThreads);
	args.resize(numThreads);

    SEC_PRINT("Spawning %d threads\n", numThreads);
	for (unsigned int i=0; i<threads.size(); ++i) {
		args[i].id = SEC_OBJECTID_USER_BASE + i;

        pthread_create(&threads[i], NULL, concurrent_vendor128, &args[i]);
	}

    SEC_PRINT("Waiting for threads to complete\n");
    for (unsigned int i=0; i<threads.size(); ++i)
    {
        pthread_join(threads[i], NULL);
    }

    SEC_PRINT("Threads completed\n");

    //check results
    SEC_PRINT("Checking results\n");
    for (unsigned int i=0; i<args.size(); ++i)
    {
    	if (SEC_RESULT_SUCCESS != args[i].res) {
    		return SEC_RESULT_FAILURE;
    	}
    }

    return SEC_RESULT_SUCCESS;
}

struct RsaArgs {
	SEC_OBJECTID id;
	TestKey pub;
	TestKey priv;
	TestKc kc;

	Sec_Result res;
};

void *concurrent_rsa(void *arg)
{
	RsaArgs *args = (RsaArgs *) arg;

	args->res = testCipherSingle(
			args->id,
			args->pub,
			args->priv,
			args->kc,
			SEC_STORAGELOC_RAM,
			SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING,
			SEC_CIPHERMODE_DECRYPT,
			SEC_AES_BLOCK_SIZE);

	return NULL;
}

Sec_Result testConcurrentRsa(TestKey pub, TestKey priv, TestKc kc, SEC_SIZE numThreads) {

	std::vector<pthread_t> threads;
	std::vector<RsaArgs> args;
	threads.resize(numThreads);
	args.resize(numThreads);

    SEC_PRINT("Spawning %d threads\n", numThreads);
	for (unsigned int i=0; i<threads.size(); ++i) {
		args[i].id = SEC_OBJECTID_USER_BASE + i;
		args[i].pub = pub;
		args[i].priv = priv;
		args[i].kc = kc;

        pthread_create(&threads[i], NULL, concurrent_rsa, &args[i]);
	}

    SEC_PRINT("Waiting for threads to complete\n");
    for (unsigned int i=0; i<threads.size(); ++i)
    {
        pthread_join(threads[i], NULL);
    }

    SEC_PRINT("Threads completed\n");

    //check results
    SEC_PRINT("Checking results\n");
    for (unsigned int i=0; i<args.size(); ++i)
    {
    	if (SEC_RESULT_SUCCESS != args[i].res) {
    		return SEC_RESULT_FAILURE;
    	}
    }

    return SEC_RESULT_SUCCESS;
}
