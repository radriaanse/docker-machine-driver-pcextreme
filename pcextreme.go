package pcextreme

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"

	"crypto/md5"
	"net/http"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
	"github.com/pkg/errors"
	"github.com/xanzy/go-cloudstack/cloudstack"
	"gopkg.in/yaml.v2"
)

const (
	driverName             = "pcextreme"
	defaultAPIURL          = "https://api.auroracompute.eu/" + defaultZone
	defaultZone            = "ams"
	defaultServiceOffering = "Agile 2G"
	defaultDiskOffering    = "20 GB"
	defaultTemplate        = "CoreOS Stable"
	defaultSSHUser         = "core"
	defaultAsyncJobTimeout = 300
	diskDataType           = "DATADISK"
)

var (
	dockerPort = 2376
	swarmPort  = 3376
	keyExists  bool
)

type configError struct {
	option string
}

func (e *configError) Error() string {
	return fmt.Sprintf("PCextreme driver requires the --pcextreme-%s option", e.option)
}

// Driver implements the libmachine/drivers.Driver interface
type Driver struct {
	*drivers.BaseDriver
	ID                string
	APIURL            string
	APIKey            string
	SecretKey         string
	HTTPGETOnly       bool
	JobTimeOut        int64
	SSHKeyPair        string
	CIDRList          []string
	Template          string
	TemplateID        string
	ServiceOffering   string
	ServiceOfferingID string
	DeleteVolumes     bool
	DiskOffering      string
	DiskOfferingID    string
	DiskSize          int
	Zone              string
	ZoneID            string
	UserDataFile      string
	UserData          string
	Tags              []string
	DisplayName       string
}

type userDataYAML struct {
	SSHAuthorizedKeys []string `yaml:"ssh_authorized_keys,omitempty"`
	SSHKeys           struct {
		RSAPrivate string `yaml:"rsa_private,omitempty"`
		RSAPublic  string `yaml:"rsa_public,omitempty"`
	} `yaml:"ssh_keys,omitempty"`
}

// GetCreateFlags registers the flags this driver adds to
// "docker hosts create"
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "pcextreme-api-url",
			Usage:  "pcextreme API URL",
			EnvVar: "pcextreme_API_URL",
		},
		mcnflag.StringFlag{
			Name:   "pcextreme-api-key",
			Usage:  "pcextreme API key",
			EnvVar: "pcextreme_API_KEY",
		},
		mcnflag.StringFlag{
			Name:   "pcextreme-secret-key",
			Usage:  "pcextreme API secret key",
			EnvVar: "pcextreme_SECRET_KEY",
		},
		mcnflag.BoolFlag{
			Name:   "pcextreme-http-get-only",
			Usage:  "Only use HTTP GET to execute pcextreme API",
			EnvVar: "pcextreme_HTTP_GET_ONLY",
		},
		mcnflag.IntFlag{
			Name:   "pcextreme-timeout",
			Usage:  "time(seconds) allowed to complete async job",
			Value:  defaultAsyncJobTimeout,
			EnvVar: "pcextreme_TIMEOUT",
		},
		mcnflag.StringFlag{
			Name:   "pcextreme-ssh-user",
			Usage:  "pcextreme SSH user",
			Value:  defaultSSHUser,
			EnvVar: "pcextreme_SSH_USER",
		},
		mcnflag.StringSliceFlag{
			Name:  "pcextreme-cidr",
			Usage: "Source CIDR to give access to the machine. default 0.0.0.0/0",
		},
		mcnflag.StringFlag{
			Name:   "pcextreme-template",
			Usage:  "pcextreme template",
			Value:  defaultTemplate,
			EnvVar: "pcextreme_TEMPLATE",
		},
		mcnflag.StringFlag{
			Name:  "pcextreme-template-id",
			Usage: "pcextreme template id",
		},
		mcnflag.StringFlag{
			Name:   "pcextreme-service-offering",
			Usage:  "pcextreme service offering",
			Value:  defaultServiceOffering,
			EnvVar: "pcextreme_SERVICE_OFFERING",
		},
		mcnflag.StringFlag{
			Name:  "pcextreme-service-offering-id",
			Usage: "pcextreme service offering id",
		},
		mcnflag.StringFlag{
			Name:   "pcextreme-zone",
			Usage:  "pcextreme zone",
			Value:  defaultZone,
			EnvVar: "pcextreme_ZONE",
		},
		mcnflag.StringFlag{
			Name:  "pcextreme-zone-id",
			Usage: "pcextreme zone id",
		},
		mcnflag.StringFlag{
			Name:   "pcextreme-userdata-file",
			Usage:  "pcextreme Userdata file",
			EnvVar: "pcextreme_USERDATA_FILE",
		},
		mcnflag.StringSliceFlag{
			Name:  "pcextreme-resource-tag",
			Usage: "key:value resource tags to be created",
		},
		mcnflag.StringFlag{
			Name:   "pcextreme-disk-offering",
			Usage:  "pcextreme disk offering",
			Value:  defaultDiskOffering,
			EnvVar: "pcextreme_DISK_OFFERING",
		},
		mcnflag.StringFlag{
			Name:  "pcextreme-disk-offering-id",
			Usage: "pcextreme disk offering id",
		},
		mcnflag.IntFlag{
			Name:   "pcextreme-disk-size",
			Usage:  "Disk offering custom size",
			EnvVar: "pcextreme_CUSTOM_DISK_SIZE",
		},
		mcnflag.BoolFlag{
			Name:  "pcextreme-delete-volumes",
			Usage: "Whether or not to delete data volumes associated with the machine upon removal",
		},
		mcnflag.StringFlag{
			Name:  "pcextreme-displayname",
			Usage: "pcextreme virtual machine displayname",
		},
	}
}

// NewDriver creates the driver with it's specified config
func NewDriver(hostName, storePath string) drivers.Driver {
	driver := &Driver{
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
	return driver
}

// DriverName returns the name of the driver as it is registered
func (d *Driver) DriverName() string {
	return driverName
}

// GetSSHHostname returns a hostname used for connecting via SSH
func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

// GetSSHUsername returns an username used for connecting via SSH
func (d *Driver) GetSSHUsername() string {
	return d.SSHUser
}

// SetConfigFromFlags configures the driver with the object that was returned
// by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.APIURL = flags.String("pcextreme-api-url")
	d.APIKey = flags.String("pcextreme-api-key")
	d.SecretKey = flags.String("pcextreme-secret-key")
	d.HTTPGETOnly = flags.Bool("pcextreme-http-get-only")
	d.JobTimeOut = int64(flags.Int("pcextreme-timeout"))
	d.SSHUser = flags.String("pcextreme-ssh-user")
	d.CIDRList = flags.StringSlice("pcextreme-cidr")
	d.Tags = flags.StringSlice("pcextreme-resource-tag")
	d.DeleteVolumes = flags.Bool("pcextreme-delete-volumes")
	d.DiskSize = flags.Int("pcextreme-disk-size")
	d.DisplayName = flags.String("pcextreme-displayname")
	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmDiscovery = flags.String("swarm-discovery")
	if err := d.setZone(flags.String("pcextreme-zone"), flags.String("pcextreme-zone-id")); err != nil {
		return err
	}
	if err := d.setTemplate(flags.String("pcextreme-template"), flags.String("pcextreme-template-id")); err != nil {
		return err
	}
	if err := d.setServiceOffering(flags.String("pcextreme-service-offering"), flags.String("pcextreme-service-offering-id")); err != nil {
		return err
	}
	if err := d.setUserData(flags.String("pcextreme-userdata-file")); err != nil {
		return err
	}
	if err := d.setDiskOffering(flags.String("pcextreme-disk-offering"), flags.String("pcextreme-disk-offering-id")); err != nil {
		return err
	}
	if d.DisplayName == "" {
		d.DisplayName = d.MachineName
	}
	d.SSHKeyPair = d.MachineName
	if d.APIURL == "" {
		return &configError{option: "api-url"}
	}
	if d.APIKey == "" {
		return &configError{option: "api-key"}
	}
	if d.SecretKey == "" {
		return &configError{option: "secret-key"}
	}
	if d.Template == "" {
		return &configError{option: "template"}
	}
	if d.ServiceOffering == "" {
		return &configError{option: "service-offering"}
	}
	if d.Zone == "" {
		return &configError{option: "zone"}
	}
	if len(d.CIDRList) == 0 {
		d.CIDRList = []string{"0.0.0.0/0"}
	}
	return nil
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g. tcp://1.2.3.4:2376
func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tcp://%s:%d", ip, dockerPort), nil
}

// GetIP returns the IP that this host is available at
func (d *Driver) GetIP() (string, error) {
	return d.IPAddress, nil
}

// GetState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetState() (state.State, error) {
	cs := d.getClient()
	vm, count, err := cs.VirtualMachine.GetVirtualMachineByID(d.ID, d.setParams)
	if err != nil {
		return state.Error, err
	}

	if count == 0 {
		return state.None, fmt.Errorf("Machine does not exist, use create command to create it")
	}

	switch vm.State {
	case "Starting":
		return state.Starting, nil
	case "Running":
		return state.Running, nil
	case "Stopping":
		return state.Running, nil
	case "Stopped":
		return state.Stopped, nil
	case "Destroyed":
		return state.Stopped, nil
	case "Expunging":
		return state.Stopped, nil
	case "Migrating":
		return state.Paused, nil
	case "Error":
		return state.Error, nil
	case "Unknown":
		return state.Error, nil
	case "Shutdowned":
		return state.Stopped, nil
	}

	return state.None, nil
}

// PreCreateCheck allows for pre-create operations to make sure a driver is ready for creation
func (d *Driver) PreCreateCheck() error {
	if err := d.checkKeyPairByName(); err != nil {
		return err
	}

	if err := d.checkInstance(); err != nil {
		return err
	}

	return nil
}

// Create a host using the driver's config
func (d *Driver) Create() error {
	cs := d.getClient()

	if err := d.createKeyPair(); err != nil {
		return err
	}
	p := cs.VirtualMachine.NewDeployVirtualMachineParams(
		d.ServiceOfferingID, d.TemplateID, d.ZoneID)
	p.SetName(d.MachineName)
	p.SetDisplayname(d.DisplayName)
	log.Infof("Setting Keypair for VM: %s", d.SSHKeyPair)
	p.SetKeypair(d.SSHKeyPair)
	if d.UserData != "" {
		p.SetUserdata(d.UserData)
	}
	if d.DiskOfferingID != "" {
		p.SetDiskofferingid(d.DiskOfferingID)
		if d.DiskSize != 0 {
			p.SetSize(int64(d.DiskSize))
		}
	}
	if err := d.createSecurityGroup(); err != nil {
		return err
	}
	p.SetSecuritygroupnames([]string{d.MachineName})
	log.Info("Creating CloudStack instance...")
	vm, err := cs.VirtualMachine.DeployVirtualMachine(p)
	if err != nil {
		return err
	}
	d.ID = vm.Id
	if len(d.Tags) > 0 {
		if err := d.createTags(); err != nil {
			return err
		}
	}

	d.IPAddress = vm.Nic[0].Ipaddress

	return nil
}

// Remove a host
func (d *Driver) Remove() error {
	cs := d.getClient()
	p := cs.VirtualMachine.NewDestroyVirtualMachineParams(d.ID)
	if err := d.deleteKeyPair(); err != nil {
		return err
	}
	log.Info("Removing PCextreme instance...")
	if _, err := cs.VirtualMachine.DestroyVirtualMachine(p); err != nil {
		return err
	}
	if err := d.deleteSecurityGroup(); err != nil {
		return err
	}
	if d.DeleteVolumes {
		if err := d.deleteVolumes(); err != nil {
			return err
		}
	}
	return nil
}

// Start a host
func (d *Driver) Start() error {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}

	if vmstate == state.Running {
		log.Info("Machine is already running")
		return nil
	}

	if vmstate == state.Starting {
		log.Info("Machine is already starting")
		return nil
	}

	cs := d.getClient()
	p := cs.VirtualMachine.NewStartVirtualMachineParams(d.ID)

	if _, err = cs.VirtualMachine.StartVirtualMachine(p); err != nil {
		return err
	}

	return nil
}

// Stop a host gracefully
func (d *Driver) Stop() error {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}

	if vmstate == state.Stopped {
		log.Info("Machine is already stopped")
		return nil
	}

	cs := d.getClient()
	p := cs.VirtualMachine.NewStopVirtualMachineParams(d.ID)

	if _, err = cs.VirtualMachine.StopVirtualMachine(p); err != nil {
		return err
	}

	return nil
}

// Restart a host.
func (d *Driver) Restart() error {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}

	if vmstate == state.Stopped {
		return fmt.Errorf("Machine is stopped, use start command to start it")
	}

	cs := d.getClient()
	p := cs.VirtualMachine.NewRebootVirtualMachineParams(d.ID)

	if _, err = cs.VirtualMachine.RebootVirtualMachine(p); err != nil {
		return err
	}

	return nil
}

// Kill stops a host forcefully
func (d *Driver) Kill() error {
	return d.Stop()
}

func (d *Driver) getClient() *cloudstack.CloudStackClient {
	cs := cloudstack.NewAsyncClient(d.APIURL, d.APIKey, d.SecretKey, false)
	cs.HTTPGETOnly = d.HTTPGETOnly
	cs.AsyncTimeout(d.JobTimeOut)
	return cs
}

func (d *Driver) setZone(zone string, zoneID string) error {
	d.Zone = zone
	d.ZoneID = zoneID

	if d.Zone == "" && d.ZoneID == "" {
		return nil
	}

	cs := d.getClient()

	var z *cloudstack.Zone
	var err error
	if d.ZoneID != "" {
		z, _, err = cs.Zone.GetZoneByID(d.ZoneID, d.setParams)
	} else {
		z, _, err = cs.Zone.GetZoneByName(d.Zone, d.setParams)
	}
	if err != nil {
		return fmt.Errorf("Unable to get zone: %v", err)
	}

	d.Zone = z.Name
	d.ZoneID = z.Id

	log.Debugf("zone: %q", d.Zone)
	log.Debugf("zone id: %q", d.ZoneID)

	return nil
}

func (d *Driver) setTemplate(templateName string, templateID string) error {
	d.Template = templateName
	d.TemplateID = templateID

	if d.Template == "" && d.TemplateID == "" {
		return nil
	}

	if d.ZoneID == "" {
		return fmt.Errorf("Unable to get template: zone is not set")
	}

	cs := d.getClient()
	var template *cloudstack.Template
	var err error
	if d.TemplateID != "" {
		template, _, err = cs.Template.GetTemplateByID(d.TemplateID, "executable", d.setParams)
	} else {
		template, _, err = cs.Template.GetTemplateByName(d.Template, "executable", d.ZoneID, d.setParams)
	}
	if err != nil {
		return fmt.Errorf("Unable to get template: %v", err)
	}

	d.TemplateID = template.Id
	d.Template = template.Name

	log.Debugf("template id: %q", d.TemplateID)
	log.Debugf("template name: %q", d.Template)

	return nil
}

func (d *Driver) setServiceOffering(serviceoffering string, serviceofferingID string) error {
	d.ServiceOffering = serviceoffering
	d.ServiceOfferingID = serviceofferingID

	if d.ServiceOffering == "" && d.ServiceOfferingID == "" {
		return nil
	}

	cs := d.getClient()
	var service *cloudstack.ServiceOffering
	var err error
	if d.ServiceOfferingID != "" {
		service, _, err = cs.ServiceOffering.GetServiceOfferingByID(d.ServiceOfferingID, d.setParams)
	} else {
		service, _, err = cs.ServiceOffering.GetServiceOfferingByName(d.ServiceOffering, d.setParams)
	}
	if err != nil {
		return fmt.Errorf("Unable to get service offering: %v", err)
	}

	d.ServiceOfferingID = service.Id
	d.ServiceOffering = service.Name

	log.Debugf("service offering id: %q", d.ServiceOfferingID)
	log.Debugf("service offering name: %q", d.ServiceOffering)

	return nil
}

func (d *Driver) setDiskOffering(diskOffering string, diskOfferingID string) error {
	d.DiskOffering = diskOffering
	d.DiskOfferingID = diskOfferingID

	if d.DiskOffering == "" && d.DiskOfferingID == "" {
		return nil
	}

	cs := d.getClient()
	var disk *cloudstack.DiskOffering
	var err error
	if d.DiskOfferingID != "" {
		disk, _, err = cs.DiskOffering.GetDiskOfferingByID(d.DiskOfferingID, d.setParams)
	} else {
		disk, _, err = cs.DiskOffering.GetDiskOfferingByName(d.DiskOffering, d.setParams)
	}
	if err != nil {
		return fmt.Errorf("Unable to get disk offering: %v", err)
	}

	d.DiskOfferingID = disk.Id
	d.DiskOffering = disk.Name

	log.Debugf("disk offering id: %q", d.DiskOfferingID)
	log.Debugf("disk offering name: %q", d.DiskOffering)

	return nil
}

func (d *Driver) setUserData(userDataFile string) error {
	var data []byte
	var err error
	if userDataFile == "" {
		return nil
	}

	if strings.HasPrefix(userDataFile, "http") {
		data, err = d.readUserDataFromURL(userDataFile)

		if err != nil {
			return fmt.Errorf("Failed to read userdata from url %s: %s", d.UserDataFile, err)
		}

	} else {

		data, err = ioutil.ReadFile(userDataFile)
		if err != nil {
			return fmt.Errorf("Failed to read user data file from path %s: %s", d.UserDataFile, err)
		}
	}

	d.UserData = base64.StdEncoding.EncodeToString(data)

	return nil
}

func (d *Driver) readUserDataFromURL(userDataURL string) ([]byte, error) {
	c := &http.Client{}

	resp, err := c.Get(userDataURL)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)

}

func (d *Driver) checkKeyPairByName() error {
	cs := d.getClient()
	log.Infof("Checking if SSH key pair (%v) already exists...", d.SSHKeyPair)
	p := cs.SSH.NewListSSHKeyPairsParams()
	p.SetName(d.SSHKeyPair)
	res, err := cs.SSH.ListSSHKeyPairs(p)
	if err != nil {
		return err
	}
	if res.Count > 0 {

		if res.SSHKeyPairs[0].Name == d.SSHKeyPair {
			keyExists = true
			return nil
		}
	}

	keyExists = false
	return nil
}

func (d *Driver) getPubKeyFingerprint(pub string) (string, error) {

	parts := strings.Fields(string(pub))
	if len(parts) < 2 {
		return "", errors.New("Bad pub key")
	}

	k, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	fp := md5.Sum([]byte(k))

	var fSum []string

	fmt.Print("MD5:")
	for i, b := range fp {

		fSum = append(fSum, fmt.Sprintf("%02x", b))
		if i < len(fp)-1 {
			fSum = append(fSum, ":")
		}
	}

	return strings.Join(fSum, ""), nil

}

func (d *Driver) checkKeyPairByFingerprint(pubKey string) (bool, error) {
	cs := d.getClient()

	fp, err := d.getPubKeyFingerprint(pubKey)

	if err != nil {
		return false, err
	}

	log.Infof("Checking for matching public key fingerprints...", d.SSHKeyPair)
	p := cs.SSH.NewListSSHKeyPairsParams()
	p.SetFingerprint(fp)
	res, err := cs.SSH.ListSSHKeyPairs(p)
	if err != nil {
		return false, err
	}
	if res.Count > 0 {
		for _, c := range res.SSHKeyPairs {
			if c.Fingerprint == fp {
				log.Infof("Found matching fingerprint, using key pair: %s", c.Name)
				d.SSHKeyPair = c.Name
				return true, nil
			}
		}
	}

	return false, nil
}

func (d *Driver) checkInstance() error {
	cs := d.getClient()

	log.Infof("Checking if instance (%v) already exists...", d.MachineName)

	p := cs.VirtualMachine.NewListVirtualMachinesParams()
	p.SetName(d.MachineName)
	p.SetZoneid(d.ZoneID)
	res, err := cs.VirtualMachine.ListVirtualMachines(p)
	if err != nil {
		return err
	}
	if res.Count > 0 {
		return fmt.Errorf("Instance (%v) already exists", d.SSHKeyPair)
	}
	return nil
}

func (d *Driver) createKeyPair() error {
	cs := d.getClient()
	var publicKey []byte
	var err error

	if keyExists {
		log.Infof("Using %s keypair", d.SSHKeyPair)
		return nil
	}

	if d.UserDataFile != "" {
		userDataContents, err := ioutil.ReadFile(d.UserDataFile)

		if err != nil {
			return err
		}

		sshKeyYaml := &userDataYAML{}

		if err != nil {
			return err
		}

		if err := yaml.Unmarshal(userDataContents, sshKeyYaml); err != nil {
			return err
		}
		log.Infof("Setting publicKey to %s", sshKeyYaml.SSHAuthorizedKeys[0])
		publicKey = []byte(sshKeyYaml.SSHAuthorizedKeys[0])

		if err := d.writeSSHKeys(sshKeyYaml.SSHKeys.RSAPrivate, sshKeyYaml.SSHAuthorizedKeys[0]); err != nil {
			return err
		}

	} else {

		if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
			return err
		}

		publicKey, err = ioutil.ReadFile(d.GetSSHKeyPath() + ".pub")
		if err != nil {
			return err
		}

	}

	exists, err := d.checkKeyPairByFingerprint(string(publicKey))

	if err != nil {
		return err
	}

	if !exists {
		log.Infof("Registering SSH key pair %s", d.SSHKeyPair)
		p := cs.SSH.NewRegisterSSHKeyPairParams(d.SSHKeyPair, string(publicKey))
		if _, err := cs.SSH.RegisterSSHKeyPair(p); err != nil {
			return err
		}
	}

	return nil
}

func (d *Driver) deleteKeyPair() error {
	cs := d.getClient()

	log.Infof("Deleting SSH key pair...")

	fp, err := ioutil.ReadFile(d.SSHKeyPath + ".pub")

	if err != nil {
		return err
	}

	inUse, err := d.checkKeyPairByFingerprint(string(fp))

	if err != nil {
		return err
	}

	if inUse {
		log.Infof("Key %s is still in use for another VM, skipping key deletion", string(fp))
		return nil
	}

	p := cs.SSH.NewDeleteSSHKeyPairParams(d.SSHKeyPair)

	if _, err := cs.SSH.DeleteSSHKeyPair(p); err != nil {
		// Throw away the error because it most likely means that a key doesn't exist
		// It is ok because we can use the same key for multiple machines.
		log.Warnf("Key may not exist: %s", err)
		return nil
	}

	return nil
}

func (d *Driver) deleteVolumes() error {
	cs := d.getClient()

	log.Info("Deleting volumes...")

	p := cs.Volume.NewListVolumesParams()
	p.SetVirtualmachineid(d.ID)
	volResponse, err := cs.Volume.ListVolumes(p)
	if err != nil {
		return err
	}
	for _, v := range volResponse.Volumes {
		if v.Type != diskDataType {
			continue
		}
		p := cs.Volume.NewDetachVolumeParams()
		p.SetId(v.Id)
		_, err := cs.Volume.DetachVolume(p)
		if err != nil {
			return err
		}
		_, err = cs.Volume.DeleteVolume(cs.Volume.NewDeleteVolumeParams(v.Id))
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) createSecurityGroup() error {
	log.Debugf("Creating security group ...")
	cs := d.getClient()

	p1 := cs.SecurityGroup.NewCreateSecurityGroupParams(d.MachineName)
	if _, err := cs.SecurityGroup.CreateSecurityGroup(p1); err != nil {
		return err
	}

	p2 := cs.SecurityGroup.NewAuthorizeSecurityGroupIngressParams()
	p2.SetSecuritygroupname(d.MachineName)
	p2.SetProtocol("tcp")
	p2.SetCidrlist(d.CIDRList)

	p2.SetStartport(22)
	p2.SetEndport(22)
	if _, err := cs.SecurityGroup.AuthorizeSecurityGroupIngress(p2); err != nil {
		return err
	}

	p2.SetStartport(dockerPort)
	p2.SetEndport(dockerPort)
	if _, err := cs.SecurityGroup.AuthorizeSecurityGroupIngress(p2); err != nil {
		return err
	}

	if d.SwarmMaster {
		p2.SetStartport(swarmPort)
		p2.SetEndport(swarmPort)
		if _, err := cs.SecurityGroup.AuthorizeSecurityGroupIngress(p2); err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) deleteSecurityGroup() error {
	log.Debugf("Deleting security group ...")
	cs := d.getClient()

	p := cs.SecurityGroup.NewDeleteSecurityGroupParams()
	p.SetName(d.MachineName)
	if _, err := cs.SecurityGroup.DeleteSecurityGroup(p); err != nil {
		return err
	}
	return nil
}

func (d *Driver) createTags() error {
	log.Info("Creating resource tags ...")
	cs := d.getClient()
	tags := make(map[string]string)
	for _, t := range d.Tags {
		parts := strings.SplitN(t, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid resource tags format, each tag must be on the format KEY:VALUE")
		}
		tags[parts[0]] = parts[1]
	}
	params := cs.Resourcetags.NewCreateTagsParams([]string{d.ID}, "UserVm", tags)
	_, err := cs.Resourcetags.CreateTags(params)
	return err
}

func (d *Driver) setParams(c *cloudstack.CloudStackClient, p interface{}) error {
	if o, ok := p.(interface {
		SetZoneid(string)
	}); ok && d.ZoneID != "" {
		o.SetZoneid(d.ZoneID)
	}
	return nil
}
func (d *Driver) writeSSHKeys(priv, pub string) error {

	if priv == "" {
		return errors.New("A private key must be passed in the userdata file under the ssh_keys")
	}

	log.Infof("Writing first private key found in userdata file to %s", d.StorePath)
	if err := ioutil.WriteFile(d.GetSSHKeyPath(), []byte(priv), 0600); err != nil {
		return err
	}

	log.Infof("Writing public key to id_rsa to %s.pub", d.GetSSHKeyPath())
	if err := ioutil.WriteFile(fmt.Sprintf("%s.pub", d.GetSSHKeyPath()), []byte(pub), 0600); err != nil {
		return err
	}

	return nil
}
