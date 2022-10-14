const {
  clearAllUsers,
  getLastSmsCode,
  createUserWithMultiFactor,
  createVerifiedUser,
  getRandomPhoneNumber,
  signInUserWithMultiFactor,
} = require('./helpers');

const TEST_EMAIL = 'test@example.com';
const TEST_PASS = 'test1234';

describe('multi-factor', function () {
  beforeEach(async function () {
    await clearAllUsers();
    await firebase.auth().createUserWithEmailAndPassword(TEST_EMAIL, TEST_PASS);
    if (firebase.auth().currentUser) {
      await firebase.auth().signOut();
      await Utils.sleep(50);
    }
  });
  it('has no multi-factor information if not enrolled', async function () {
    await firebase.auth().signInWithEmailAndPassword(TEST_EMAIL, TEST_PASS);
    const { multiFactor } = firebase.auth().currentUser;
    multiFactor.should.be.an.Object();
    multiFactor.enrolledFactors.should.be.an.Array();
    multiFactor.enrolledFactors.length.should.equal(0);
    return Promise.resolve();
  });
  it('can not reuse session after logout', async function () {
    const { email, password } = await createUserWithMultiFactor();

    try {
      await firebase.auth().signInWithEmailAndPassword(email, password);
    } catch (e) {
      e.message.should.equal(
        '[auth/multi-factor-auth-required] Please complete a second factor challenge to finish signing into this account.',
      );
      const resolver = firebase.auth.getMultiFactorResolver(firebase.auth(), e);
      const oldHints = resolver.hints[0];
      const oldSession = resolver.session;

      await firebase.auth().signInWithEmailAndPassword(TEST_EMAIL, TEST_PASS);
      firebase.auth().currentUser.email.should.equal(TEST_EMAIL);

      try {
        await firebase.auth().verifyPhoneNumberWithMultiFactorInfo(oldHints, oldSession);
      } catch (e) {
        e.message.should.equal(
          '[auth/invalid-multi-factor-session] No resolver for session found. Is the session id correct?',
        );
        return Promise.resolve();
      }

      return Promise.resolve();
    }

    return Promise.reject();
  });

  describe('sign-in', function () {
    it(':android: requires multi-factor auth when enrolled', async function () {
      const { phoneNumber, email, password } = await createUserWithMultiFactor();

      try {
        await firebase.auth().signInWithEmailAndPassword(email, password);
      } catch (e) {
        e.message.should.equal(
          '[auth/multi-factor-auth-required] Please complete a second factor challenge to finish signing into this account.',
        );
        const resolver = firebase.auth.getMultiFactorResolver(firebase.auth(), e);
        resolver.should.be.an.Object();
        resolver.hints.should.be.an.Array();
        resolver.hints.length.should.equal(1);
        resolver.session.should.be.a.String();

        const verificationId = await firebase
          .auth()
          .verifyPhoneNumberWithMultiFactorInfo(resolver.hints[0], resolver.session);
        verificationId.should.be.a.String();

        let verificationCode = await getLastSmsCode(phoneNumber);
        if (verificationCode == null) {
          // iOS simulator uses a masked phone number
          const maskedNumber = '+********' + phoneNumber.substring(phoneNumber.length - 4);
          verificationCode = await getLastSmsCode(maskedNumber);
        }
        const credential = firebase.auth.PhoneAuthProvider.credential(
          verificationId,
          verificationCode,
        );
        const multiFactorAssertion = firebase.auth.PhoneMultiFactorGenerator.assertion(credential);
        return resolver
          .resolveSignIn(multiFactorAssertion)
          .then(userCreds => {
            userCreds.should.be.an.Object();
            userCreds.user.should.be.an.Object();
            userCreds.user.email.should.equal('verified@example.com');
            userCreds.user.multiFactor.should.be.an.Object();
            userCreds.user.multiFactor.enrolledFactors.length.should.equal(1);
            return Promise.resolve();
          })
          .catch(e => {
            return Promise.reject(e);
          });
      }

      return Promise.reject(new Error('Multi-factor users need to handle an exception on sign-in'));
    });
    it(':android: reports an error when providing an invalid sms code', async function () {
      const { phoneNumber, email, password } = await createUserWithMultiFactor();

      try {
        await firebase.auth().signInWithEmailAndPassword(email, password);
      } catch (e) {
        e.message.should.equal(
          '[auth/multi-factor-auth-required] Please complete a second factor challenge to finish signing into this account.',
        );
        const resolver = firebase.auth.getMultiFactorResolver(firebase.auth(), e);
        const verificationId = await firebase
          .auth()
          .verifyPhoneNumberWithMultiFactorInfo(resolver.hints[0], resolver.session);

        const credential = firebase.auth.PhoneAuthProvider.credential(verificationId, 'incorrect');
        const assertion = firebase.auth.PhoneMultiFactorGenerator.assertion(credential);
        try {
          await resolver.resolveSignIn(assertion);
        } catch (e) {
          // Android / iOS and Web spell SMS differently
          e.message
            .toLocaleLowerCase()
            .should.equal(
              '[auth/invalid-verification-code] The SMS verification code used to create the phone auth credential is invalid. Please resend the verification code sms and be sure to use the verification code provided by the user.'.toLocaleLowerCase(),
            );

          const verificationId = await firebase
            .auth()
            .verifyPhoneNumberWithMultiFactorInfo(resolver.hints[0], resolver.session);
          const verificationCode = await getLastSmsCode(phoneNumber);
          const credential = firebase.auth.PhoneAuthProvider.credential(
            verificationId,
            verificationCode,
          );
          const assertion = firebase.auth.PhoneMultiFactorGenerator.assertion(credential);
          await resolver.resolveSignIn(assertion);
          firebase.auth().currentUser.email.should.equal(email);
          return Promise.resolve();
        }
      }
      return Promise.reject();
    });
    it(':android: reports an error when providing an invalid verification code', async function () {
      const { phoneNumber, email, password } = await createUserWithMultiFactor();

      try {
        await firebase.auth().signInWithEmailAndPassword(email, password);
      } catch (e) {
        e.message.should.equal(
          '[auth/multi-factor-auth-required] Please complete a second factor challenge to finish signing into this account.',
        );
        const resolver = firebase.auth.getMultiFactorResolver(firebase.auth(), e);
        await firebase
          .auth()
          .verifyPhoneNumberWithMultiFactorInfo(resolver.hints[0], resolver.session);
        const verificationCode = await getLastSmsCode(phoneNumber);

        const credential = firebase.auth.PhoneAuthProvider.credential(
          'incorrect',
          verificationCode,
        );
        const assertion = firebase.auth.PhoneMultiFactorGenerator.assertion(credential);
        try {
          await resolver.resolveSignIn(assertion);
        } catch (e) {
          e.message.should.equal(
            '[auth/invalid-verification-id] The verification ID used to create the phone auth credential is invalid.',
          );

          return Promise.resolve();
        }
      }
      return Promise.reject();
    });
  });

  describe('enroll', function () {
    it(":android: can't enroll an existing user without verified email", async function () {
      await firebase.auth().signInWithEmailAndPassword(TEST_EMAIL, TEST_PASS);

      try {
        const multiFactorUser = await firebase.auth.multiFactor(firebase.auth());
        const session = await multiFactorUser.getSession();
        await firebase
          .auth()
          .verifyPhoneNumberForMultiFactor({ phoneNumber: getRandomPhoneNumber(), session });
      } catch (e) {
        // TODO fix in code to match web
        e.message.should.equal(
          '[auth/unknown] This operation requires a verified email. [ Need to verify email first before enrolling second factors. ]',
        );
        e.code.should.equal('auth/unknown');
        return Promise.resolve();
      }

      return Promise.reject(new Error('Should throw error for unverified user.'));
    });

    it(':android: can enroll new factor', async function () {
      try {
        await createVerifiedUser('verified@example.com', 'test123');
        const phoneNumber = getRandomPhoneNumber();

        should.deepEqual(firebase.auth().currentUser.multiFactor.enrolledFactors, []);
        const multiFactorUser = await firebase.auth.multiFactor(firebase.auth());

        const session = await multiFactorUser.getSession();

        const verificationId = await firebase
          .auth()
          .verifyPhoneNumberForMultiFactor({ phoneNumber, session });
        const verificationCode = await getLastSmsCode(phoneNumber);
        const cred = firebase.auth.PhoneAuthProvider.credential(verificationId, verificationCode);
        const multiFactorAssertion = firebase.auth.PhoneMultiFactorGenerator.assertion(cred);
        await multiFactorUser.enroll(multiFactorAssertion, 'Hint displayName');

        const enrolledFactors = firebase.auth().currentUser.multiFactor.enrolledFactors;
        enrolledFactors.length.should.equal(1);
        enrolledFactors[0].displayName.should.equal('Hint displayName');
        enrolledFactors[0].factorId.should.equal('phone');
        enrolledFactors[0].uid.should.be.a.String();
        enrolledFactors[0].enrollmentTime.should.be.a.String();
      } catch (e) {
        return Promise.reject(e);
      }
      return Promise.resolve();
    });
    it(':android: can enroll new factor without display name', async function () {
      try {
        await createVerifiedUser('verified@example.com', 'test123');
        const phoneNumber = getRandomPhoneNumber();

        should.deepEqual(firebase.auth().currentUser.multiFactor.enrolledFactors, []);
        const multiFactorUser = await firebase.auth.multiFactor(firebase.auth());

        const session = await multiFactorUser.getSession();

        const verificationId = await firebase
          .auth()
          .verifyPhoneNumberForMultiFactor({ phoneNumber, session });
        const verificationCode = await getLastSmsCode(phoneNumber);
        const cred = firebase.auth.PhoneAuthProvider.credential(verificationId, verificationCode);
        const multiFactorAssertion = firebase.auth.PhoneMultiFactorGenerator.assertion(cred);
        await multiFactorUser.enroll(multiFactorAssertion);

        const enrolledFactors = firebase.auth().currentUser.multiFactor.enrolledFactors;
        enrolledFactors.length.should.equal(1);
        should.equal(enrolledFactors[0].displayName, null);
      } catch (e) {
        return Promise.reject(e);
      }
      return Promise.resolve();
    });
    it(':android: can enroll multiple factors', async function () {
      const { email, password, phoneNumber } = await createUserWithMultiFactor();
      await signInUserWithMultiFactor(email, password, phoneNumber);

      const anotherNumber = getRandomPhoneNumber();
      const multiFactorUser = await firebase.auth.multiFactor(firebase.auth());

      const session = await multiFactorUser.getSession();
      const verificationId = await firebase
        .auth()
        .verifyPhoneNumberForMultiFactor({ phoneNumber: anotherNumber, session });
      const verificationCode = await getLastSmsCode(anotherNumber);
      const cred = firebase.auth.PhoneAuthProvider.credential(verificationId, verificationCode);
      const multiFactorAssertion = firebase.auth.PhoneMultiFactorGenerator.assertion(cred);
      const displayName = 'Another displayName';
      await multiFactorUser.enroll(multiFactorAssertion, displayName);

      const enrolledFactors = firebase.auth().currentUser.multiFactor.enrolledFactors;
      enrolledFactors.length.should.equal(2);
      const matchingFactor = enrolledFactors.find(factor => factor.displayName === displayName);
      matchingFactor.should.be.an.Object();
      matchingFactor.uid.should.be.a.String();
      matchingFactor.enrollmentTime.should.be.a.String();
      matchingFactor.factorId.should.equal('phone');

      return Promise.resolve();
    });
    it(':android: can not enroll the same factor twice', async function () {
      // This test should probably be implemented but doesn't work:
      // Every time the same phone number requests a verification code,
      // the emulator endpoint does not return a code, even though the emulator log
      // prints a code.
      /*
        await clearAllUsers();
        const { email, password, phoneNumber } = await createUserWithMultiFactor();
        await signInUserWithMultiFactor(email, password, phoneNumber);
        const multiFactorUser = await firebase.auth.multiFactor(firebase.auth());
        const session = await multiFactorUser.getSession();

        const verificationId = await firebase
          .auth()
          .verifyPhoneNumberForMultiFactor({ phoneNumber, session });
        const verificationCode = await getLastSmsCode(phoneNumber);

        const cred = firebase.auth.PhoneAuthProvider.credential(verificationId, verificationCode);
        const multiFactorAssertion = firebase.auth.PhoneMultiFactorGenerator.assertion(cred);
        const displayName = 'Another displayName';
        try {
          await multiFactorUser.enroll(multiFactorAssertion, displayName);
        } catch (e) {
          console.error(e);
          return Promise.resolve();
        }
        return Promise.reject();
        */
    });

    it(':android: throws an error for wrong verification id', async function () {
      const { phoneNumber, email, password } = await createUserWithMultiFactor();

      // GIVEN a MultiFactorResolver
      let resolver = null;
      try {
        await firebase.auth().signInWithEmailAndPassword(email, password);
        return Promise.reject();
      } catch (e) {
        e.message.should.equal(
          '[auth/multi-factor-auth-required] Please complete a second factor challenge to finish signing into this account.',
        );
        resolver = firebase.auth.getMultiFactorResolver(firebase.auth(), e);
      }
      await firebase
        .auth()
        .verifyPhoneNumberWithMultiFactorInfo(resolver.hints[0], resolver.session);

      // AND I request a verification code
      const verificationCode = await getLastSmsCode(phoneNumber);
      // AND I use an incorrect verificationId
      const credential = firebase.auth.PhoneAuthProvider.credential(
        'wrongVerificationId',
        verificationCode,
      );
      const multiFactorAssertion = firebase.auth.PhoneMultiFactorGenerator.assertion(credential);

      try {
        // WHEN I try to resolve the sign-in
        await resolver.resolveSignIn(multiFactorAssertion);
      } catch (e) {
        // THEN an error message is thrown
        e.message.should.equal(
          '[auth/invalid-verification-id] The verification ID used to create the phone auth credential is invalid.',
        );
        return Promise.resolve();
      }
      return Promise.reject();
    });
    it('throws an error for unknown sessions', async function () {
      const { email, password } = await createUserWithMultiFactor();
      let resolver = null;
      try {
        await firebase.auth().signInWithEmailAndPassword(email, password);
        return Promise.reject();
      } catch (e) {
        e.message.should.equal(
          '[auth/multi-factor-auth-required] Please complete a second factor challenge to finish signing into this account.',
        );
        resolver = firebase.auth.getMultiFactorResolver(firebase.auth(), e);
      }

      try {
        await firebase
          .auth()
          .verifyPhoneNumberWithMultiFactorInfo(resolver.hints[0], 'unknown-session');
      } catch (e) {
        // THEN an error message is thrown
        e.message.should.equal(
          '[auth/invalid-multi-factor-session] No resolver for session found. Is the session id correct?',
        );
        return Promise.resolve();
      }
      return Promise.reject();
    });
    it('throws an error for unknown verification code', async function () {
      const { email, password } = await createUserWithMultiFactor();

      // GIVEN a MultiFactorResolver
      let resolver = null;
      try {
        await firebase.auth().signInWithEmailAndPassword(email, password);
        return Promise.reject();
      } catch (e) {
        e.message.should.equal(
          '[auth/multi-factor-auth-required] Please complete a second factor challenge to finish signing into this account.',
        );
        resolver = firebase.auth.getMultiFactorResolver(firebase.auth(), e);
      }
      const verificationId = await firebase
        .auth()
        .verifyPhoneNumberWithMultiFactorInfo(resolver.hints[0], resolver.session);

      // AND I use an incorrect verificationId
      const credential = firebase.auth.PhoneAuthProvider.credential(
        verificationId,
        'wrong-verification-code',
      );
      const multiFactorAssertion = firebase.auth.PhoneMultiFactorGenerator.assertion(credential);

      try {
        // WHEN I try to resolve the sign-in
        await resolver.resolveSignIn(multiFactorAssertion);
      } catch (e) {
        // THEN an error message is thrown
        const actualMessage = e.message.toLocaleLowerCase();
        const expectedMessage =
          '[auth/invalid-verification-code] The sms verification code used to create the phone auth credential is invalid. Please resend the verification code sms and be sure to use the verification code provided by the user.'.toLocaleLowerCase();
        should.equal(actualMessage, expectedMessage);

        return Promise.resolve();
      }
      return Promise.reject();
    });

    it(':android: can not enroll with phone authentication (unsupported primary factor)', async function () {
      // GIVEN a user that only signs in with phone
      const testPhone = getRandomPhoneNumber();
      const confirmResult = await firebase.auth().signInWithPhoneNumber(testPhone);
      const lastSmsCode = await getLastSmsCode(testPhone);
      await confirmResult.confirm(lastSmsCode);

      // WHEN they attempt to enroll a second factor
      const multiFactorUser = await firebase.auth.multiFactor(firebase.auth());
      const session = await multiFactorUser.getSession();
      try {
        await firebase.auth().verifyPhoneNumberForMultiFactor({ phoneNumber: '+1123123', session });
      } catch (e) {
        e.message.should.equal(
          '[auth/unknown] Enrolling a second factor or signing in with a multi-factor account requires sign-in with a supported first factor. [ MFA is not available for the given first factor. ]',
        );
        return Promise.resolve();
      }
      return Promise.reject(
        new Error('Enrolling a second factor when using phone authentication is not supported.'),
      );
    });
  });
});
