// SUP-474: `spf-master` is an ES module. A CommonJS consumer that loads this
// library must not be forced to load `spf-master` as well, because some of them
// cannot. Only `spfRecordResolvesWithinDnsLookupsLimit` needs it, so the load
// has to wait until a caller asks for that function.
let mockSpfMasterLoaded = false;

jest.mock('spf-master', () => {
  mockSpfMasterLoaded = true;
  return {
    SpfInspector: jest.fn(async () => ({ found: { includes: [], domains: [] } })),
  };
});

describe('spf-master loading', () => {
  beforeEach(() => {
    mockSpfMasterLoaded = false;
  });

  it('should not load spf-master when a consumer requires the library', () => {
    jest.isolateModules(() => {
      require('./index');
    });

    expect(mockSpfMasterLoaded).toBe(false);
  });

  it('should load spf-master when the inspector is first used', async () => {
    let emailSetup;
    jest.isolateModules(() => {
      emailSetup = require('./index');
    });
    expect(mockSpfMasterLoaded).toBe(false);

    await emailSetup.spfRecordResolvesWithinDnsLookupsLimit('example.com', 10);

    expect(mockSpfMasterLoaded).toBe(true);
  });
});
