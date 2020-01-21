import pytest

from subkey import (
    KeyringPair,
)

MESSAGE = b"My Message"


@pytest.mark.parametrize(
    "suri,key_type,public,exp_signature",
    [
        # ed25519 dev keys
        (
            '//Alice',
            'ed25519',
            # Public Key
            '88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee',
            # Signature for MESSAGE
            '6789805518a36d54dafccadf148c67e17c5fbe1fc549b46d7877604d99ab7217'
            'aa73d53d27c271125066f1da91912d920c889a087ec7c2224844477edb7b4100',
        ),
        (
            '//Alice//stash',
            'ed25519',
            # Public Key
            '451781cd0c5504504f69ceec484cc66e4c22a2b6a9d20fb1a426d91ad074a2a8',
            # Signature for MESSAGE
            '7166451182237ede32ab163bef103e1392360f52305d8a6dc379e00af5e89f97'
            'e17430bbe52d8e2f87108fa3489a307643f3a03bf964a87dd8278fe157624a03',
        ),
        (
            '//Bob',
            'ed25519',
            # Public Key
            'd17c2d7823ebf260fd138f2d7e27d114c0145d968b5ff5006125f2414fadae69',
            # Signature for MESSAGE
            'bc9253061c958fc7a428bb5fc6ca4bc90afc48e18417e995d11a9fcc8095b543'
            '0fe796c590d68debe10b956ec860cfb9ee7ab929c58b78b5776f0712c8fec801',
        ),
        (
            '//Bob//stash',
            'ed25519',
            # Public Key
            '292684abbb28def63807c5f6e84e9e8689769eb37b1ab130d79dbfbf1b9a0d44',
            # Signature for MESSAGE
            '4a107031279abd0d5ad821e2fac5f50a123ad912eb40c7b7f773fabcedb48c47'
            '3b2de733cef65fbd8192bce3a66a99c6898c555be7c3a554a71c416116228d06',
        ),
        (
            '//Charlie',
            'ed25519',
            # Public Key
            '439660b36c6c03afafca027b910b4fecf99801834c62a5e6006f27d978de234f',
            # Signature for MESSAGE
            '3199afb0747d04f8af41878a49f80383f9c1b9e22bbc7cd85a4b239b3b3595fa'
            '605e07802c5c1a6ce4e8117d6a96fbbef615a2eb38ba16347059b319c7ea460f',
        ),
        (
            '//Dave',
            'ed25519',
            # Public Key
            '5e639b43e0052c47447dac87d6fd2b6ec50bdd4d0f614e4299c665249bbd09d9',
            # Signature for MESSAGE
            '59c84dd6b19af6a0bbbb135a7b6ebf663cfdd891a4452894af5d721a2fc8ad5c'
            '5afe0c85c606bb6e7ccd3aff1bd781cdce9dca770d26d688415e81aace42ec0f',
        ),
        (
            '//Eve',
            'ed25519',
            # Public Key
            '1dfe3e22cc0d45c70779c1095f7489a8ef3cf52d62fbd8c2fa38c9f1723502b5',
            # Signature for MESSAGE
            '21cbfd5303623aae38089567900fed68cc378ed7853deba53bad970c264c4371'
            '52b0b906a81a0102536518345ef33ced7656a822c5c0381bbfccca5859ed3405',
        ),
        (
            '//Ferdie',
            'ed25519',
            # Public Key
            '568cb4a574c6d178feb39c27dfc8b3f789e5f5423e19c71633c748b9acf086b5',
            # Signature for MESSAGE
            'fc0967f87de4ac129db295a764170792481fafdc83c614027b9f4106f8732214'
            '3b1218f64b6c0b2926ab354d9c771aa29f3581ad86f42adaca118f2fa09e5809',
        ),
        # sr25519 dev keys
        (
            '//Alice',
            'sr25519',
            # Public Key
            'd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d',
            # Signature for MESSAGE
            '0c4a60b0de06ad297f1b81f854a240592dd26a8c2cdeab50e9341ec6e7554936'
            '4ab40684da7f55b94b95e7eacc50a525d36387526b94e177e196424fc7d05183',
        ),
        (
            '//Alice//stash',
            'sr25519',
            # Public Key
            'be5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f',
            # Signature for MESSAGE
            '8a09b4cc6e979a9b2557c1e64ac0e51caa04e7695235b0348f5e016d625e986f'
            '68911bf4737bc5045bd6f2ca66ee661a2e09916b1b6a3c6837552b805d78808e',
        ),
        (
            '//Bob',
            'sr25519',
            # Public Key
            '8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48',
            # Signature for MESSAGE
            'b89956c8db4ea16ee2cafd57b278fd707356b65c9ff6cdb59b12a9b4a263c16f'
            '71047fa69fc05f888523c4be264f12d3ae1cad94ebec15b2a274cd1f11bece8c',
        ),
        (
            '//Bob//stash',
            'sr25519',
            # Public Key
            'fe65717dad0447d715f660a0a58411de509b42e6efb8375f562f58a554d5860e',
            # Signature for MESSAGE
            '6630d660626c639a1b24812f9748fce646d32972e19092a85df2452146d1c955'
            '25e3726835600336622f8e0a3ac331e2b60460baf0fe8785168248204d0c8989',
        ),
        (
            '//Charlie',
            'sr25519',
            # Public Key
            '90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22',
            # Signature for MESSAGE
            '64fe47cac6e03e83e7199b6c43b9eab42939f6e746f4dd1be6d1aca788801641'
            '7800f7aee17bb2151a9537b3ce61956647c7d20c3a2d3cbfce42b425d3942c8d',
        ),
        (
            '//Dave',
            'sr25519',
            # Public Key
            '306721211d5404bd9da88e0204360a1a9ab8b87c66c1bc2fcdd37f3c2222cc20',
            # Signature for MESSAGE
            '1cf6e27cd39bdd816c6e02caa06125734ee0c1c4f7b24d9f910e6109eeb1a316'
            '29de29aed04b3f15ac1005479dfeb919f3f0dfc7556cbe0100a55669523e268e',
        ),
        (
            '//Eve',
            'sr25519',
            # Public Key
            'e659a7a1628cdd93febc04a4e0646ea20e9f5f0ce097d9a05290d4a9e054df4e',
            # Signature for MESSAGE
            '02b5523759649ee9bea31dd771ea2b36921b6161cf606619764aa8128e20b45e'
            'f4600b811b8dab35e0b94ce2ec11b029d78cfaaa0eadcc7aae8dc076bc0da485',
        ),
        (
            '//Ferdie',
            'sr25519',
            # Public Key
            '1cbd2d43530a44705ad088af313e18f80b53ef16b36177cd4b77b846f2a5f07c',
            # Signature for MESSAGE
            '2689f71a2cb3e3c03146bdbb4c0fa91b8d4d04a777de8bbce31af52c6bba3f54'
            '98f5fb25a99353dbbc1cfd519210b49e3200580ad4efc4e920e241ddbf4c208a',
        ),
        # secp256k1 dev keys
        (
            '//Alice',
            'secp256k1',
            # Public Key
            '0a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1'
            '2da8d65fae6d63a4abca410b7e50d50cd95d36001c28712fd2adf944adb03b12',
            # Signature for MESSAGE
            'af5ce40ebdb53de3528ccb69a8f4331be71e9e9505aa137a257908ed178a5159'
            '7cd28645e15f50e57a7ae6b1c3dc35b2afeb209e14e45e14a0a55d0846c01545'
            '01',
        ),
        (
            '//Alice//stash',
            'secp256k1',
            # Public Key
            'c6a1c2194fa966d30bc4b9c4d5140e9a899d456372dae0e4ef230fd7d2197e72'
            '507f616416df58260388790cf875c232e352e6caf2784c961d7252eccf990181',
            # Signature for MESSAGE
            '4f4f992866f2318c58ba9f67ff801b030dbaee705614a25228b43bdaae8b4b5f'
            '335f8c657dc5a840723dd68fb7f7da0db35b1a3d1aced741c7be153a069bf4cc'
            '01',
        ),
        (
            '//Bob',
            'secp256k1',
            # Public Key
            '90084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27'
            'baf6745460a3da4942b61272bdd092c6efb9e19a2622b6d8e46d0ab2e3c8e1a5',
            # Signature for MESSAGE
            '130b2f03b9fa6feba0b0beb7be4d107133ff78af7c41575fdec0c89e71921462'
            '4e5ed1c7e56edd75c76df686e9dcc63438961dfcc2ba51d4a71a103aa3053321'
            '01',
        ),
        (
            '//Bob//stash',
            'secp256k1',
            # Public Key
            'b9a427c7067d109c69e55d3d196a7d84d5f607fe30c3896846bfdf72a3d782b9'
            '3b4d9d1e636cd1c0df4da28cdd3d7c460b2d29a8925f68a81cebc4fe186653a9',
            # Signature for MESSAGE
            'da749137a028fc2fedf6d7d5403657433764ad040e0d40862c0f95711c3af78f'
            '27bc842945fbc313532604ef5e0cc33c0c2525ad06b16041d218ac46eb409759'
            '00',
        ),
        (
            '//Charlie',
            'secp256k1',
            # Public Key
            '89411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb'
            '1a7d900bcd1368372292131e2bf810ee8b2245df0ed8052d9ff6a1db708e2a63',
            # Signature for MESSAGE
            '357c36fe2e76a54c143b0103c4336a49eaabd3b0b61ece2a411cf4d2f7463a4a'
            '3f9a0687b0470f8133c04525a29c315ff9e2e98c96fb1ea42095f4d824745aaa'
            '00',
        ),
        (
            '//Dave',
            'secp256k1',
            # Public Key
            'bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c'
            '0effffe1475b0cbcce9f53eec4c0ee3ffb54a5ef4ccc79a3b2768911d6da28bb',
            # Signature for MESSAGE
            '1d22ef493459e5b9b2bb3dd8d35de3fb2ddebd99b96dafe03546cc2c5cba3334'
            '62b5167b2d33946824d46789a60c5e96affbd9d81a434559d75daa6051246d73'
            '00',
        ),
        (
            '//Eve',
            'secp256k1',
            # Public Key
            '1d10105e323c4afce225208f71a6441ee327a65b9e646e772500c74d31f669aa'
            'a750a94a9da76aa0b707a0b1446a4b067ee639a44be554b7892629e3efe57a4b',
            # Signature for MESSAGE
            'bceb9c47d840965ed1fac6c874d5f63827acb19c25a6bbe5527532b1719e691f'
            '7c97e3c3350563ff076e1897073df4959526605dacc76b0fa96120df0d97cfcf'
            '01',
        ),
        (
            '//Ferdie',
            'secp256k1',
            # Public Key
            '91f1217d5a04cb83312ee3d88a6e6b33284e053e6ccfc3a90339a0299d12967c'
            '022f729bc7752fffb8984ba69715c0cb5f6ff850cb1d481a40c87bfb236ffd7a',
            # Signature for MESSAGE
            '9c3354c433eb5d6ae6f9173c5c2e6f8e768e89bb6f9993b495e690c7122ca218'
            '1389da3a48a12a543388dff7a9349672fc8422a51488147df039d32468f3a546'
            '01',
        ),
    ]
)
def test_pairs(suri, key_type, public, exp_signature):
    """
    Test against known keypairs (obtained from ParityTech's subkey utility)
    Note: default is ed25519 crypto
    """
    # Verify key generation from SURI matches
    pair = KeyringPair(suri, key_type)
    assert pair.public.hex() == public
    # Verify a signature this library generates
    sig = pair.sign(MESSAGE)
    assert pair.verify(MESSAGE, sig)
    # Verify a statically known signature
    assert pair.verify(MESSAGE, bytes.fromhex(exp_signature))
