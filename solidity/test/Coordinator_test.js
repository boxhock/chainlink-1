import {
  abiEncode,
  accessSolidityContractTransferMethod,
  assertActionThrows,
  bigNum,
  consumer,
  checkPublicABI,
  calculateSAID,
  checkServiceAgreementPresent,
  checkServiceAgreementAbsent,
  deploy,
  executeServiceAgreementBytes,
  functionSelector,
  getLatestEvent,
  initiateServiceAgreement,
  initiateServiceAgreementCall,
  newAddress,
  newHash,
  newServiceAgreement,
  oracleNode,
  pad0xHexTo256Bit,
  padNumTo256Bit,
  personalSign,
  recoverPersonalSignature,
  requestDataBytes,
  requestDataFrom,
  runRequestId,
  sixMonthsFromNow,
  stranger,
  strip0x,
  toHex,
  toWei
} from './support/helpers'

contract('Coordinator', () => {
  const sourcePath = 'Coordinator.sol'
  let coordinator, link

  beforeEach(async () => {
    console.log('deploying link token')
    link = await deploy('link_token/contracts/LinkToken.sol')
    console.log('deploying coordinator')
    coordinator = await deploy(sourcePath, link.address)
    console.log('deployments complete')
  })

  it('has a limited public interface', () => {
    checkPublicABI(artifacts.require(sourcePath), [
      'getPackedArguments',
      'getId',
      'executeServiceAgreement',
      'fulfillData',
      'getId',
      'initiateServiceAgreement',
      'onTokenTransfer',
      'serviceAgreements'
    ])
  })

  const agreedPayment = 1
  const agreedExpiration = 2
  const endAt = sixMonthsFromNow()
  const agreedOracles = [
    '0x70AEc4B9CFFA7b55C0711b82DD719049d615E21d',
    '0xd26114cd6EE289AccF82350c8d8487fedB8A0C07'
  ]
  const requestDigest = '0x85820c5ec619a1f517ee6cfeff545ec0ca1a90206e1a38c47f016d4137e801dd'
  const args =
        [ agreedPayment, agreedExpiration, endAt, agreedOracles, requestDigest ]
  const expectedBinaryArgs = [
    '0x',
    ...[agreedPayment, agreedExpiration, endAt].map(padNumTo256Bit),
    ...agreedOracles.map(pad0xHexTo256Bit),
    strip0x(requestDigest)
  ].join('').toLowerCase()

  describe('#getPackedArguments', () => {
    it('returns the following value, given these arguments', async () => {
      const result = await coordinator.getPackedArguments.call(...args)

      assert.equal(result, expectedBinaryArgs)
    })
  })

  describe('#getId', () => {
    it('matches the ID generated by the oracle off-chain', async () => {
      const expectedBinaryArgsSha3 = web3.utils.sha3(
        expectedBinaryArgs, { encoding: 'hex' })
      const result = await coordinator.getId.call(...args)

      assert.equal(result, expectedBinaryArgsSha3)
    })
  })

  describe('#initiateServiceAgreement', () => {
    let agreement
    before(async () => {
      agreement = await newServiceAgreement({oracles: [oracleNode]})
    })

    context('with valid oracle signatures', () => {
      it('saves a service agreement struct from the parameters', async () => {
        await initiateServiceAgreement(coordinator, agreement)
        await checkServiceAgreementPresent(coordinator, agreement)
      })

      it('returns the SAID', async () => {
        const sAID = await initiateServiceAgreementCall(coordinator, agreement)
        assert.equal(sAID, agreement.id)
      })

      it('logs an event', async () => {
        await initiateServiceAgreement(coordinator, agreement)
        const event = await getLatestEvent(coordinator)
        assert.equal(agreement.id, event.args.said)
      })
    })

    context('with an invalid oracle signatures', () => {
      let badOracleSignature, badRequestDigestAddr
      before(async () => {
        const sAID = calculateSAID(agreement)
        badOracleSignature = await personalSign(stranger, sAID)
        badRequestDigestAddr = recoverPersonalSignature(sAID, badOracleSignature)
        assert.equal(stranger.toLowerCase(), toHex(badRequestDigestAddr))
      })

      it('saves no service agreement struct, if signatures invalid',
              async () => {
                assertActionThrows(
                  async () => await initiateServiceAgreement(
                    coordinator,
                    Object.assign(agreement,
                                  { oracleSignature: badOracleSignature })))
                await checkServiceAgreementAbsent(coordinator, agreement.id)
              })
    })

    context('Validation of service agreement deadlines', () => {
      it('Rejects a service agreement with an endAt date in the past', async () => {
        await assertActionThrows(
          async () => await initiateServiceAgreement(
            coordinator,
            Object.assign(agreement, { endAt: 1000 })))
        await checkServiceAgreementAbsent(coordinator, agreement.id)
        return
      })
    })
  })

  describe('#executeServiceAgreement', () => {
    const fHash = functionSelector('requestedBytes32(bytes32,bytes32)')
    const to = '0x80e29acb842498fe6591f020bd82766dce619d43'
    let agreement
    before(async () => {
      agreement = await newServiceAgreement({oracles: [oracleNode]})
    })

    beforeEach(async () => {
      await initiateServiceAgreement(coordinator, agreement)
      await link.transfer(consumer, toWei(1000).toString())
    })

    context('when called through the LINK token with enough payment', () => {      
      let payload, tx
      beforeEach(async function setupServiceAgreement() {
        const payload = executeServiceAgreementBytes(
          agreement.id, to, fHash, '1', '')
        tx = await link.transferAndCall(coordinator.address, agreement.payment,
                                        payload, { from: consumer })
      })

      it('logs an event', async () => {
        const log = tx.receipt.logs[2]
        assert.equal(coordinator.address, log.address)

        // If updating this test, be sure to update services.ServiceAgreementExecutionLogTopic.
        // (Which see for the calculation of this hash.)
        let eventSignature = '0x6d6db1f8fe19d95b1d0fa6a4bce7bb24fbf84597b35a33ff95521fac453c1529'
        assert.equal(eventSignature, log.topics[0])

        assert.equal(agreement.id, log.topics[1],
                     "Logged ServiceAgreement ID doesn't match")
        assert(bigNum(consumer).eq(bigNum(log.topics[2])),
              "Logged consumer contract address doesn't match")
        assert(bigNum(agreement.payment).eq(bigNum(log.topics[3])),
              "Logged payment amount amount doesn't match")
      })
    })

    context('when called through the LINK token with not enough payment', () => {
      it('throws an error', async () => {
        const calldata = executeServiceAgreementBytes(agreement.id, to, fHash, '1', '')
        const underPaid = bigNum(agreement.payment).sub(bigNum(1))

        await assertActionThrows(async () => {
          await link.transferAndCall(coordinator.address, underPaid.toString(),
                                     calldata, { from: consumer })
        })
      })
    })

    context('when not called through the LINK token', () => {
      it('reverts', async () => {
        await assertActionThrows(async () => {
          await coordinator.executeServiceAgreement(
            0, 0, 1, agreement.id, to, fHash, 'id', '', { from: consumer })
        })
      })
    })
  })

  describe('#fulfillData', () => {
    const externalId = '17'
    let agreement, mock, internalId
    beforeEach(async () => {
      agreement = await newServiceAgreement({oracles: [oracleNode]})
      await initiateServiceAgreement(coordinator, agreement)

      mock = await deploy('examples/GetterSetter.sol')
      const fHash = functionSelector('requestedBytes32(bytes32,bytes32)')

      const payload = executeServiceAgreementBytes(agreement.id, mock.address, fHash, externalId, '')
      const tx = await link.transferAndCall(coordinator.address, agreement.payment, payload)
      internalId = runRequestId(tx.receipt.logs[2])
    })

    context('cooperative consumer', () => {
      context('when called by a non-owner', () => {
        xit('raises an error', async () => {
          await assertActionThrows(async () => {
            await coordinator.fulfillData(internalId, 'Hello World!', { from: stranger })
          })
        })
      })

      context('when called by an owner', () => {
        it.skip('raises an error if the request ID does not exist', async () => {
          await assertActionThrows(async () => {
            await coordinator.fulfillData(
              0xdeadbeef, 'Hello World!', { from: oracleNode })
          })
        })

        it('sets the value on the requested contract', async () => {
          await coordinator.fulfillData(
            internalId, 'Hello World!', { from: oracleNode })

          const mockRequestId = await mock.requestId.call()
          assert.equal(externalId, web3.utils.toUtf8(mockRequestId))

          const currentValue = await mock.getBytes32.call()
          assert.equal('Hello World!', web3.utils.toUtf8(currentValue))
        })

        it('does not allow a request to be fulfilled twice', async () => {
          await coordinator.fulfillData(internalId, 'First message!', { from: oracleNode })
          await assertActionThrows(async () => {
            await coordinator.fulfillData(internalId, 'Second message!!', { from: oracleNode })
          })
        })
      })
    })

    context('with a malicious requester', () => {
      const paymentAmount = toWei(1)

      it.only('cannot cancel before the expiration', async () => {
        mock = await deploy(
          'examples/MaliciousRequester.sol', link.address, coordinator.address)
        await link.transfer(mock.address, paymentAmount)
        await assertActionThrows(async () => {
          await mock.maliciousRequestCancel()
        })
      })

      it('cannot call functions on the LINK token through callbacks', async () => {
        const fHash = functionSelector('transfer(address,uint256)')
        const addressAsRequestId = abiEncode(['address'], [stranger])
        const args = requestDataBytes(agreement.id, link.address, fHash, addressAsRequestId, '')

        assertActionThrows(async () => {
          await requestDataFrom(coordinator, link, paymentAmount, args)
        })
      })
    })

    context('with a malicious consumer', () => {
      const paymentAmount = toWei(1)

      beforeEach(async () => {
        mock = await deploy('examples/MaliciousServiceAgreementConsumer.sol', link.address, coordinator.address)
        await link.transfer(mock.address, paymentAmount.toString())
      })

      context('fails during fulfillment', () => {
        beforeEach(async () => {
          const req = await mock.requestData('assertFail(bytes32,bytes32)')
          internalId = runRequestId(req.receipt.logs[3])
        })

        // needs coordinator withdrawal functionality to meet parity
        xit('allows the oracle node to receive their payment', async () => {
          await coordinator.fulfillData(internalId, 'hack the planet 101', { from: oracleNode })

          const balance = await link.balanceOf.call(oracleNode)
          assert.isTrue(balance.equals(0))

          await coordinator.withdraw(oracleNode, paymentAmount, { from: oracleNode })
          const newBalance = await link.balanceOf.call(oracleNode)
          assert.isTrue(paymentAmount.equals(newBalance))
        })

        it("can't fulfill the data again", async () => {
          await coordinator.fulfillData(internalId, 'hack the planet 101', { from: oracleNode })
          await assertActionThrows(async () => {
            await coordinator.fulfillData(internalId, 'hack the planet 102', { from: oracleNode })
          })
        })
      })

      context('calls selfdestruct', () => {
        beforeEach(async () => {
          const req = await mock.requestData('doesNothing(bytes32,bytes32)')
          internalId = runRequestId(req.receipt.logs[3])
          await mock.remove()
        })

        // needs coordinator withdrawal functionality to meet parity
        xit('allows the oracle node to receive their payment', async () => {
          await coordinator.fulfillData(internalId, 'hack the planet 101', { from: oracleNode })

          const balance = await link.balanceOf.call(oracleNode)
          assert.isTrue(balance.equals(0))

          await coordinator.withdraw(oracleNode, paymentAmount, { from: oracleNode })
          const newBalance = await link.balanceOf.call(oracleNode)
          assert.isTrue(paymentAmount.equals(newBalance))
        })
      })

      context('request is canceled during fulfillment', () => {
        beforeEach(async function requestCancellationSetup() {
          const req = await mock.requestData('cancelRequestOnFulfill(bytes32,bytes32)')
          internalId = runRequestId(req.receipt.logs[3])

          const mockBalance = await link.balanceOf.call(mock.address)
          assert.isTrue(mockBalance.equals(0))
        })

        // needs coordinator withdrawal functionality to meet parity
        xit('allows the oracle node to receive their payment', async () => {
          await coordinator.fulfillData(internalId, 'hack the planet 101', { from: oracleNode })

          const mockBalance = await link.balanceOf.call(mock.address)
          assert.isTrue(mockBalance.equals(0))

          const balance = await link.balanceOf.call(oracleNode)
          assert.isTrue(balance.equals(0))

          await coordinator.withdraw(oracleNode, paymentAmount, { from: oracleNode })
          const newBalance = await link.balanceOf.call(oracleNode)
          assert.isTrue(paymentAmount.equals(newBalance))
        })

        it("can't fulfill the data again", async () => {
          await coordinator.fulfillData(internalId, 'hack the planet 101', { from: oracleNode })
          await assertActionThrows(async () => {
            await coordinator.fulfillData(internalId, 'hack the planet 102', { from: oracleNode })
          })
        })
      })

      context('requester lies about amount of LINK sent', () => {
        it('the oracle uses the amount of LINK actually paid', async () => {
          const req = await mock.requestData('assertFail(bytes32,bytes32)')
          const log = req.receipt.logs[3]

          assert(web3.utils.toWei(bigNum(1)).eq(bigNum(log.topics[3])),
                "Oracle did not use the amount of LINK actually paid")
        })
      })
    })
  })
})
