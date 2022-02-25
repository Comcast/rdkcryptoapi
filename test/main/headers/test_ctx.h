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

#ifndef TEST_CTX_H_
#define TEST_CTX_H_

#include <list>
#include <utility>
#include <algorithm>
#include <string.h>
#include <string>
#include "sec_security.h"
#include "test_creds.h"

//#define ENABLE_FULL_LOGS

#ifdef ENABLE_FULL_LOGS
	#define DELAYED_LOG 0
#else
	#define DELAYED_LOG 1
#endif

enum TestState {
	TESTRESULT_SUCCEEDED = 0,
	TESTRESULT_FAILED,
	TESTRESULT_SKIPPED,
	TESTRESULT_NUM
};

#define SEC_PRINT_HEX(name, ptr, size) \
	SEC_PRINT("%s[%d]: ", name, size); Sec_PrintHex(ptr, size); SEC_PRINT("\n");
#define RUN_TEST(suite, function) \
	{ \
		int testIdx = (suite)->addTest(#function); \
		\
		if ((suite)->shouldRun(testIdx)) { \
			if (DELAYED_LOG) { Logger::init(); } \
			SEC_PRINT("\n"); \
			SEC_PRINT("%d: " #function " STARTING\n", testIdx); \
			Sec_Result res = function; \
			std::string output = DELAYED_LOG ? Logger::output() : std::string(); \
			if (DELAYED_LOG) { Logger::shutdown(); } \
			if (SEC_RESULT_SUCCESS == res) { \
				SEC_PRINT("%d: " #function " SUCCEEDED\n", testIdx); \
				(suite)->setTestState(testIdx, TESTRESULT_SUCCEEDED); \
			} else { \
				SEC_PRINT(output.c_str()); \
				SEC_PRINT("%d: " #function " FAILED\n\n", testIdx);  \
				(suite)->setTestState(testIdx, TESTRESULT_FAILED); \
			} \
		} else { \
			(suite)->setTestState(testIdx, TESTRESULT_SKIPPED); \
			if ((suite)->shouldPrint(testIdx)) { \
				SEC_PRINT("%d: " #function "\n", testIdx); \
			} \
		} \
	}

class SuiteCtx {
	typedef std::pair<const char *, TestState> TestEntry;
public:
	SuiteCtx() {}
	~SuiteCtx() {}

	void setRunParams(const std::vector<int>& runParams) { runParams_ = runParams; }
	SEC_BOOL shouldRun(int id) const { return runParams_.size() == 0 || std::find(runParams_.begin(), runParams_.end(), id) != runParams_.end(); }
	SEC_BOOL shouldPrint(int id) const { return shouldRun(id) || (runParams_.size() == 1 && runParams_[0] <= 0); }
	int addTest(const char *name) { tests_.push_back(std::make_pair(name, TESTRESULT_NUM)); return tests_.size(); }
	void setTestState(int id, TestState state) { tests_[id-1].second = state; }
	TestEntry getTestEntry(int id) const { return tests_[id-1]; }
	std::vector<int> getFailed() const;
	std::vector<int> getSucceeded() const;
	std::vector<int> getSkipped() const;
	std::vector<int> getAttempted() const;
	std::vector<int> getAll() const;

private:
	std::vector<TestEntry> tests_;
	std::vector<int> runParams_;
};

class TestCtx {
public:
	TestCtx();
	~TestCtx();

	Sec_Result init(const char *global_dir = "/tmp/sec_api_test_global", const char *app_dir = "/tmp/sec_api_test_app");

	Sec_KeyHandle *provisionKey(SEC_OBJECTID id, Sec_StorageLoc location, TestKey key, TestKc, SEC_BOOL softWrap = SEC_FALSE);
    Sec_KeyHandle *provisionKey(SEC_OBJECTID id, Sec_StorageLoc location, const SEC_BYTE *data, SEC_SIZE len, Sec_KeyContainer kc, SEC_BOOL softWrap = SEC_FALSE);
	Sec_KeyHandle *getKey(SEC_OBJECTID id);
	void releaseKey(Sec_KeyHandle *key);
	void deleteKey(SEC_OBJECTID id);

	Sec_CertificateHandle * provisionCert(SEC_OBJECTID id, Sec_StorageLoc location, TestCert cert);
	Sec_CertificateHandle *getCert(SEC_OBJECTID id);
	void releaseCert(Sec_CertificateHandle* certHandle);
	void deleteCert(SEC_OBJECTID id);

	Sec_BundleHandle * provisionBundle(SEC_OBJECTID id, Sec_StorageLoc location, const std::vector<SEC_BYTE>& bundle);
	Sec_BundleHandle *getBundle(SEC_OBJECTID id);
	void releaseBundle(Sec_BundleHandle* bundleHandle);
	void deleteBundle(SEC_OBJECTID id);

	Sec_MacHandle *acquireMac(Sec_MacAlgorithm algorithm, Sec_KeyHandle *key);
	Sec_Result releaseMac(Sec_MacHandle* macHandle, SEC_BYTE* macBuffer, SEC_SIZE* macSize);
	void releaseMac(Sec_MacHandle* macHandle);

	Sec_CipherHandle *acquireCipher(Sec_CipherAlgorithm algorithm, Sec_CipherMode mode, Sec_KeyHandle* key, SEC_BYTE* iv);
	void releaseCipher(Sec_CipherHandle *cipher);

	Sec_SignatureHandle *acquireSignature(Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode, Sec_KeyHandle* key);
	void releaseSignature(Sec_SignatureHandle *sig);

	Sec_DigestHandle *acquireDigest(Sec_DigestAlgorithm algorithm);
	Sec_Result releaseDigest(Sec_DigestHandle* digestHandle, SEC_BYTE* digestOutput, SEC_SIZE* digestSize);
	void releaseDigest(Sec_DigestHandle* digestHandle);

	Sec_RandomHandle *acquireRandom(Sec_RandomAlgorithm algorithm);
	void releaseRandom(Sec_RandomHandle* randomHandle);

	SEC_BYTE* Sec_NativeMalloc(Sec_ProcessorHandle* handle, SEC_SIZE length);
	void Sec_NativeFree(Sec_ProcessorHandle* handle, void *ptr);

	Sec_ProcessorHandle *proc() { return proc_; }

	//utils
	static void printHex(const char *label, const std::vector<SEC_BYTE>& data);
	static std::vector<SEC_BYTE> random(SEC_SIZE len);
	static std::vector<SEC_BYTE> coalesceInputs(const std::vector<std::vector<SEC_BYTE> >& inputs);
	static SEC_SIZE coalesceInputSizes(const std::vector<SEC_SIZE>& inputSizes);

private:
	Sec_ProcessorHandle *proc_;
	std::list<SEC_OBJECTID> provisionedKeys_;
	std::list<Sec_KeyHandle *> keys_;
	std::list<SEC_OBJECTID> provisionedCerts_;
	std::list<Sec_CertificateHandle *> certs_;
	std::list<SEC_OBJECTID> provisionedBundles_;
	std::list<Sec_BundleHandle *> bundles_;
	std::list<Sec_MacHandle *> macs_;
	std::list<Sec_CipherHandle *> ciphers_;
	std::list<Sec_SignatureHandle *> sigs_;
	std::list<Sec_DigestHandle *> digests_;
	std::list<Sec_RandomHandle *> randoms_;
};

class Logger {
public:
	static void init();
	static void shutdown();
	static const char *output();
};

#endif /* TEST_CTX_H_ */
