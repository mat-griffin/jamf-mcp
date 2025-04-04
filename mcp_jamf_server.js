import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import axios from 'axios';
import { z } from 'zod';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

// Create an MCP server
const server = new McpServer({
  name: 'jamf-mcp-server',
  version: '0.1.3',
});

// Jamf Pro API base URL
// e.g. https://your-server.jamfcloud.com/api
const JAMF_API_BASE_URL = process.env.JAMF_URL || 'https://yourserver.jamfcloud.com/api';

// Default credentials from environment variables
// Jamf Pro readonly username and password for the MCP server
const DEFAULT_USERNAME = process.env.JAMF_USERNAME || 'jamf_readonly';
const DEFAULT_PASSWORD = process.env.JAMF_PASSWORD || 'jamf_password';

// Optional: Enable debug logging
const DEBUG = process.env.DEBUG === 'true';

if (DEBUG) {
  console.error('Debug mode enabled');
  console.error('Using Jamf API URL:', JAMF_API_BASE_URL);
}

/**
 * Authenticate with Jamf Pro API and get a bearer token
 * @param {string} username - Jamf Pro username
 * @param {string} password - Jamf Pro password
 * @returns {Promise<string>} - Bearer token
 */
async function getJamfToken(username = DEFAULT_USERNAME, password = DEFAULT_PASSWORD) {
  const encodedCredentials = Buffer.from(`${username}:${password}`).toString('base64');
  
  try {
    const response = await axios.post(
      `${JAMF_API_BASE_URL}/v1/auth/token`,
      {},
      {
        headers: {
          'Authorization': `Basic ${encodedCredentials}`,
          'Accept': 'application/json',
        },
      }
    );
    
    console.error('Authentication successful, token received');
    return response.data.token;
  } catch (error) {
    console.error('Error getting Jamf token:', error.message);
    throw error;
  }
}

async function getComputerBySerial(serialNumber, requestedSections = []) {
  try {
    const token = await getJamfToken();
    
    // Step 1: Search for computer by serial number
    const searchUrl = `${JAMF_API_BASE_URL}/v1/computers-inventory?filter=hardware.serialNumber=="${serialNumber}"`;
    
    const searchResponse = await axios.get(searchUrl, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });
    
    const computers = searchResponse.data.results;
    
    if (!computers || computers.length === 0) {
      // Try name search as fallback
      const nameSearchUrl = `${JAMF_API_BASE_URL}/v1/computers-inventory?filter=general.name=="${serialNumber}"`;
      
      const nameSearchResponse = await axios.get(nameSearchUrl, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
        },
      });
      
      if (!nameSearchResponse.data.results || nameSearchResponse.data.results.length === 0) {
        return { error: 'No computer found with that serial number or name' };
      }
      
      // Use the first computer from name search
      return await getComputerDetails(token, nameSearchResponse.data.results[0].id, requestedSections);
    }
    
    // Get details for the first matching computer
    return await getComputerDetails(token, computers[0].id, requestedSections);
  } catch (error) {
    console.error('Error:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', JSON.stringify(error.response.data, null, 2).substring(0, 500));
    }
    return { error: error.message };
  }
}

async function getComputerById(id, requestedSections = []) {
  try {
    const token = await getJamfToken();
    return await getComputerDetails(token, id, requestedSections);
  } catch (error) {
    console.error('Error:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', JSON.stringify(error.response.data, null, 2).substring(0, 500));
    }
    return { error: error.message };
  }
}

async function getComputerDetails(token, id, requestedSections = []) {
  try {
    // Request all sections for detailed information
    const detailUrl = `${JAMF_API_BASE_URL}/v1/computers-inventory/${id}?section=GENERAL&section=DISK_ENCRYPTION&section=STORAGE&section=USER_AND_LOCATION&section=CONFIGURATION_PROFILES&section=HARDWARE&section=LOCAL_USER_ACCOUNTS&section=SECURITY&section=OPERATING_SYSTEM&section=EXTENSION_ATTRIBUTES&section=GROUP_MEMBERSHIPS`;
    
    const response = await axios.get(detailUrl, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });

    // Log the response data for debugging
    if (DEBUG) {
      console.error('API Response:', JSON.stringify({
        diskEncryption: response.data.diskEncryption,
        userAndLocation: response.data.userAndLocation
      }, null, 2));
    }
    
    // Add diskEncryption and userAndLocation to the response data
    const computerInfo = {
      ...response.data,
      diskEncryption: {
        fileVault2Enabled: response.data.diskEncryption?.fileVault2Enabled,
        fileVaultEnabled: response.data.diskEncryption?.fileVaultEnabled,
        recoveryKeyEscrowed: response.data.diskEncryption?.recoveryKeyEscrowed,
        personalRecoveryKeyValid: response.data.diskEncryption?.personalRecoveryKeyValid,
        institutionalRecoveryKeyPresent: response.data.diskEncryption?.institutionalRecoveryKeyPresent
      },
      userAndLocation: response.data.userAndLocation || {}
    };
    
    return computerInfo;
  } catch (error) {
    console.error('Error getting computer details:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', JSON.stringify(error.response.data, null, 2).substring(0, 500));
    }
    return { error: error.message };
  }
}

async function getExtensionAttributes(id, username = DEFAULT_USERNAME, password = DEFAULT_PASSWORD) {
  try {
    const token = await getJamfToken(username, password);
    
    // Try the classic API endpoint for extension attributes
    const classicUrl = `${JAMF_API_BASE_URL}/JSSResource/computers/id/${id}`;
    
    const response = await axios.get(classicUrl, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });
    
    // Log the raw response for debugging
    if (DEBUG) {
      console.error('Classic API Response:', JSON.stringify(response.data?.computer?.extension_attributes, null, 2));
    }
    
    // Extract extension attributes from the response
    const attributes = response.data?.computer?.extension_attributes || [];
    
    // Create a simplified format that matches what we need
    const extensionAttributes = attributes.map(attr => ({
      id: attr.id,
      name: attr.name,
      value: attr.value || attr.values?.[0]
    }));
    
    return {
      computerInfo: {
        id: id
      },
      extensionAttributes
    };
  } catch (error) {
    console.error('Error getting extension attributes:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', JSON.stringify(error.response.data, null, 2).substring(0, 500));
    }
    return { error: error.message };
  }
}

async function listComputers(username = DEFAULT_USERNAME, password = DEFAULT_PASSWORD, limit = 10, modelFilter = null, managedOnly = false) {
  try {
    const token = await getJamfToken(username, password);
    
    let url = `${JAMF_API_BASE_URL}/v1/computers-inventory?page=0&page-size=${limit}&sort=general.name%3Aasc`;
    
    if (modelFilter) {
      url += `&filter=hardware.model=="${modelFilter}"`;
    }
    
    if (managedOnly) {
      // Add filter for managed devices
      const managedFilter = url.includes('filter=') ? ' and ' : '&filter=';
      url += `${managedFilter}general.remoteManagement.managed==true`;
    }
    
    const response = await axios.get(url, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });
    
    return response.data.results.map(computer => ({
      id: computer.id || 'Unknown',
      serialNumber: computer.hardware?.serialNumber || 'Unknown',
      model: computer.hardware?.model || 'Unknown',
      name: computer.general?.name || 'Unknown',
      osVersion: computer.operatingSystem?.version || 'Unknown',
      managed: computer.general?.remoteManagement?.managed || false
    }));
  } catch (error) {
    console.error('Error listing computers:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', JSON.stringify(error.response.data, null, 2).substring(0, 500));
    }
    return [];
  }
}

async function getComputersByUser(userIdentifier, username = DEFAULT_USERNAME, password = DEFAULT_PASSWORD) {
  try {
    const token = await getJamfToken(username, password);
    
    // Create an array of possible search filters
    const searchFilters = [
      `userAndLocation.username=="${userIdentifier}"`,
      `userAndLocation.realname=="${userIdentifier}"`,
      `userAndLocation.email=="${userIdentifier}"`,
      `userAndLocation.email=="*${userIdentifier}*"`,
      `userAndLocation.username=="*${userIdentifier}*"`,
      `userAndLocation.realname=="*${userIdentifier}*"`
    ];
    
    let allResults = [];
    
    // Try each search filter
    for (const filter of searchFilters) {
      const url = `${JAMF_API_BASE_URL}/v1/computers-inventory?filter=${encodeURIComponent(filter)}`;
      
      try {
        const response = await axios.get(url, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/json',
          },
        });
        
        if (response.data.results && response.data.results.length > 0) {
          // Get full details for each computer found
          const computers = await Promise.all(
            response.data.results.map(computer => getComputerDetails(token, computer.id))
          );
          
          // Add unique computers to results
          computers.forEach(computer => {
            if (!allResults.some(r => r.id === computer.id)) {
              allResults.push(computer);
            }
          });
        }
      } catch (searchError) {
        console.error(`Search error with filter ${filter}:`, searchError.message);
        // Continue with next filter even if one fails
        continue;
      }
    }
    
    return allResults;
  } catch (error) {
    console.error('Error searching for computers by user:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', JSON.stringify(error.response.data, null, 2).substring(0, 500));
    }
    return { error: error.message };
  }
}

// Get firewall status from multiple sources
async function getFirewallStatus(token, computerInfo) {
  try {
    console.log('Checking firewall status for computer:', computerInfo.id);

    // Try extension attributes first
    const extUrl = `${JAMF_API_BASE_URL}/v1/computers-inventory/${computerInfo.id}/extension-attributes`;
    try {
      const extResponse = await axios.get(extUrl, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
        },
      });
      console.log('Extension Attributes Response:', JSON.stringify(extResponse.data, null, 2));
      
      // Look for firewall-related extension attributes
      const firewallAttrs = extResponse.data?.results?.filter(attr => 
        attr.name?.toLowerCase().includes('firewall') ||
        attr.description?.toLowerCase().includes('firewall')
      );
      
      if (firewallAttrs?.length > 0) {
        console.log('Found firewall-related extension attributes:', firewallAttrs);
        for (const attr of firewallAttrs) {
          const value = attr.value?.toString().toLowerCase();
          if (value === 'enabled' || value === 'on' || value === 'true' || value === '1') {
            console.log('Firewall enabled according to extension attribute:', attr.name);
            return true;
          }
        }
      }
    } catch (error) {
      console.error('Error getting extension attributes:', error.message);
    }

    // Try the MDM command status endpoint
    const mdmUrl = `${JAMF_API_BASE_URL}/v1/computers-inventory/${computerInfo.id}/mdm-management-status`;
    try {
      const mdmResponse = await axios.get(mdmUrl, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
        },
      });
      const mdmStatus = mdmResponse.data;
      console.log('MDM Status Response:', JSON.stringify({
        managementStatus: mdmStatus.managementStatus,
        securityStatus: mdmStatus.securityStatus,
        settings: mdmStatus.settings
      }, null, 2));
      
      if (mdmStatus.managementStatus?.firewallStatus === 'ENABLED' || 
          mdmStatus.securityStatus?.firewallEnabled === true ||
          mdmStatus.settings?.firewall?.enabled === true) {
        console.log('Firewall enabled according to MDM status');
        return true;
      }
    } catch (error) {
      console.error('Error getting firewall status from MDM endpoint:', error.message);
    }

    // Try the direct firewall status endpoint
    const firewallUrl = `${JAMF_API_BASE_URL}/v1/computers-inventory/${computerInfo.id}/security/firewall`;
    try {
      const firewallResponse = await axios.get(firewallUrl, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
        },
      });
      console.log('Direct Firewall Response:', JSON.stringify(firewallResponse.data, null, 2));
      
      if (firewallResponse.data && firewallResponse.data.enabled === true) {
        console.log('Firewall enabled according to direct firewall endpoint');
        return true;
      }
    } catch (error) {
      console.error('Error getting firewall status from direct endpoint:', error.message);
    }

    // Try the classic API
    const classicUrl = `${JAMF_API_BASE_URL}/classic/computers/id/${computerInfo.id}`;
    try {
      const classicResponse = await axios.get(classicUrl, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
        },
      });
      const firewallEnabled = classicResponse.data?.computer?.security?.firewall_enabled;
      console.log('Classic API Response:', JSON.stringify({
        firewallEnabled,
        security: classicResponse.data?.computer?.security
      }, null, 2));
      
      if (firewallEnabled && (
        firewallEnabled === true || 
        firewallEnabled === "true" || 
        firewallEnabled === "1" || 
        firewallEnabled.toLowerCase() === "enabled" ||
        firewallEnabled.toLowerCase() === "on"
      )) {
        console.log('Firewall enabled according to classic API');
        return true;
      }
    } catch (error) {
      console.error('Error getting firewall status from classic API:', error.message);
    }

    // Try the security endpoint
    const securityUrl = `${JAMF_API_BASE_URL}/v1/computers-inventory/${computerInfo.id}/security`;
    try {
      const securityResponse = await axios.get(securityUrl, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
        },
      });
      console.log('Security Endpoint Response:', JSON.stringify({
        firewallEnabled: securityResponse.data?.firewallEnabled,
        firewallStatus: securityResponse.data?.firewallStatus,
        firewall: securityResponse.data?.firewall,
        raw: securityResponse.data
      }, null, 2));
      
      if (securityResponse.data && (
        securityResponse.data.firewallEnabled === true || 
        securityResponse.data.firewallStatus === 'ENABLED' ||
        securityResponse.data.firewall?.enabled === true ||
        securityResponse.data.firewall?.status === 'ENABLED' ||
        securityResponse.data.firewall?.state === 'on'
      )) {
        console.log('Firewall enabled according to security endpoint');
        return true;
      }
    } catch (error) {
      console.error('Error getting firewall status from security endpoint:', error.message);
    }

    // Try the settings endpoint
    const settingsUrl = `${JAMF_API_BASE_URL}/v1/computers-inventory/${computerInfo.id}/settings`;
    try {
      const settingsResponse = await axios.get(settingsUrl, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
        },
      });
      console.log('Settings Endpoint Response:', JSON.stringify({
        security: settingsResponse.data?.security,
        raw: settingsResponse.data
      }, null, 2));
      
      if (settingsResponse.data && (
        settingsResponse.data.security?.firewall?.enabled === true ||
        settingsResponse.data.security?.firewallEnabled === true ||
        settingsResponse.data.security?.firewallStatus === 'ENABLED' ||
        settingsResponse.data.security?.firewall?.state === 'on'
      )) {
        console.log('Firewall enabled according to settings endpoint');
        return true;
      }
    } catch (error) {
      console.error('Error getting firewall status from settings endpoint:', error.message);
    }

    console.log('No endpoints reported firewall as enabled');
    return false;
  } catch (error) {
    console.error('Error in getFirewallStatus:', error.message);
    return false;
  }
}

async function getComputerInfo(identifier, username = DEFAULT_USERNAME, password = DEFAULT_PASSWORD) {
  try {
    // Try to get computer by serial number first
    let computerInfo = await getComputerBySerial(identifier);
    
    // If not found by serial, try by ID
    if (computerInfo.error) {
      computerInfo = await getComputerById(identifier);
      if (computerInfo.error) {
        throw new Error(computerInfo.error);
      }
    }
    
    // Get extension attributes
    const extAttrs = await getExtensionAttributes(computerInfo.id, username, password);
    
    // Add extension attributes to computer info
    computerInfo.extensionAttributes = extAttrs.extensionAttributes;
    
    return computerInfo;
  } catch (error) {
    console.error('Error getting computer info:', error.message);
    throw error;
  }
}

async function getSecurityStatus(identifier, username, password) {
  try {
    const computerInfo = await getComputerInfo(identifier, username, password);
    
    // Get extension attributes
    const extAttrs = await getExtensionAttributes(computerInfo.id, username, password);
    
    // Find the macOS - Location extension attribute
    let macOSLocation = "Unavailable via API - Check Jamf Pro";
    if (extAttrs && extAttrs.extensionAttributes) {
      const locationAttr = extAttrs.extensionAttributes.find(attr => 
        attr.name === "macOS - Location" || 
        attr.name === "macOS Location" || 
        attr.name === "Location"
      );
      if (locationAttr && locationAttr.value) {
        macOSLocation = locationAttr.value;
      }
    }
    
    // Log the computer info for debugging
    if (DEBUG) {
      console.error('Computer Info:', JSON.stringify({
        diskEncryption: computerInfo.diskEncryption,
        security: computerInfo.security,
        extensionAttributes: extAttrs
      }, null, 2));
    }
    
    const securityStatus = {
      device: {
        id: computerInfo.id,
        name: computerInfo.name,
        serialNumber: computerInfo.serialNumber,
        model: computerInfo.model,
        osVersion: computerInfo.osVersion,
        buildVersion: computerInfo.buildVersion,
        lastContactTime: computerInfo.lastContactTime
      },
      location: {
        macOSLocation: macOSLocation,
        username: computerInfo.userAndLocation?.username || "Unavailable via API - Check Jamf Pro",
        realName: computerInfo.userAndLocation?.realname || "Unavailable via API - Check Jamf Pro",
        email: computerInfo.userAndLocation?.email || "Unavailable via API - Check Jamf Pro",
        position: computerInfo.userAndLocation?.position || "Unavailable via API - Check Jamf Pro",
        department: computerInfo.userAndLocation?.department || "Unavailable via API - Check Jamf Pro",
        building: computerInfo.userAndLocation?.building || "Unavailable via API - Check Jamf Pro",
        room: computerInfo.userAndLocation?.room || "Unavailable via API - Check Jamf Pro",
        phone: computerInfo.userAndLocation?.phone || "Unavailable via API - Check Jamf Pro"
      },
      managementStatus: {
        managed: computerInfo.managed || false,
        supervised: computerInfo.supervised || false,
        mdmCapable: computerInfo.mdmCapable || { capable: false, capableUsers: [] },
        userApprovedMdm: computerInfo.userApprovedMdm || false,
        enrollmentMethod: computerInfo.enrollmentMethod || { id: "Unknown", objectName: "Unknown", objectType: "Unknown" },
        mdmProfileExpiration: computerInfo.mdmProfileExpiration || "Unknown"
      },
      securityControls: {
        systemIntegrityProtection: computerInfo.security?.sipStatus || "Unknown",
        gatekeeperStatus: computerInfo.security?.gatekeeperStatus || "Unknown",
        xprotectVersion: computerInfo.security?.xprotectVersion || "Unknown",
        autoLoginDisabled: computerInfo.security?.autoLoginDisabled || false,
        remoteDesktopEnabled: computerInfo.security?.remoteDesktopEnabled || false,
        activationLockEnabled: computerInfo.security?.activationLockEnabled || false,
        secureBootLevel: computerInfo.security?.secureBootLevel || "Unknown",
        externalBootLevel: computerInfo.security?.externalBootLevel || "Unknown",
        firewallEnabled: "Not available via API"
      },
      diskEncryption: {
        fileVaultStatus: computerInfo.diskEncryption?.fileVault2Enabled === true || computerInfo.diskEncryption?.fileVaultEnabled === true ? "ENABLED" : 
                        computerInfo.diskEncryption?.fileVault2Enabled === false && computerInfo.diskEncryption?.fileVaultEnabled === false ? "DISABLED" : 
                        "Unavailable via API - Check Jamf Pro",
        fileVaultPercent: computerInfo.diskEncryption?.fileVaultPercent || "Unavailable via API - Check Jamf Pro",
        recoveryKeyType: computerInfo.diskEncryption?.recoveryKeyEscrowed ? "Institutional" : 
                        computerInfo.diskEncryption?.personalRecoveryKeyValid ? "Personal" :
                        "Unavailable via API - Check Jamf Pro",
        encrypted: computerInfo.diskEncryption?.fileVault2Enabled || computerInfo.diskEncryption?.fileVaultEnabled || "Unavailable via API - Check Jamf Pro",
        encryptionDetails: computerInfo.storage?.disks?.map(disk => ({
          device: disk.device,
          encrypted: disk.encrypted || "Unavailable via API - Check Jamf Pro",
          encryptionType: disk.encryptionType || "Unavailable via API - Check Jamf Pro",
          partitions: disk.partitions?.map(partition => ({
            name: partition.name,
            fileVault2State: partition.fileVault2State || "Unavailable via API - Check Jamf Pro"
          })) || []
        })) || []
      },
      complianceItems: {
        passcodePresent: "Unavailable via API - Check Jamf Pro",
        passcodeCompliant: "Unavailable via API - Check Jamf Pro",
        passcodeCompliantWithProfile: "Unavailable via API - Check Jamf Pro",
        hardwareEncryptionEnabled: "Unavailable via API - Check Jamf Pro",
        blockLevelEncryptionCapable: "Unavailable via API - Check Jamf Pro",
        recoveryLockEnabled: "Unavailable via API - Check Jamf Pro"
      },
      userAccounts: computerInfo.userAccounts?.map(account => ({
        username: account.username,
        admin: account.admin || false,
        secureTokenEnabled: "Unavailable via API - Check Jamf Pro"
      })) || [],
      securityProfiles: computerInfo.profiles || [],
      securitySoftware: {
        antivirusInstalled: "Unavailable via API - Check Jamf Pro",
        antivirusName: "Unavailable via API - Check Jamf Pro",
        antivirusSignatureDate: "Unavailable via API - Check Jamf Pro",
        malwareInstalled: "Unavailable via API - Check Jamf Pro",
        malwareName: "Unavailable via API - Check Jamf Pro"
      }
    };

    // Build risk assessment
    const riskFactors = [];
    const recommendations = [];

    if (computerInfo.security?.sipStatus !== "ENABLED") {
      riskFactors.push("System Integrity Protection is not enabled");
      recommendations.push("Enable System Integrity Protection for enhanced system security");
    }

    if (!computerInfo.diskEncryption?.encrypted) {
      riskFactors.push("FileVault is not enabled");
      recommendations.push("Enable FileVault to protect data at rest");
    }

    if (computerInfo.userAccounts?.some(account => account.admin && !account.secureTokenEnabled)) {
      riskFactors.push("Admin account without secure token");
      recommendations.push("Enable secure token for admin account");
    }

    if (!computerInfo.security?.antivirusInstalled) {
      riskFactors.push("No antivirus software detected");
      recommendations.push("Install and configure antivirus software");
    }

    // Determine risk level
    let riskLevel = "Low";
    if (riskFactors.length > 3) {
      riskLevel = "High";
    } else if (riskFactors.length > 1) {
      riskLevel = "Medium";
    }

    return {
      ...securityStatus,
      riskAssessment: {
        riskLevel,
        riskFactors,
        recommendations
      }
    };
  } catch (error) {
    console.error('Error getting security status:', error);
    return { error: error.message };
  }
}

// Helper function to compare version numbers
function compareVersions(v1, v2) {
  const v1Parts = v1.split('.').map(Number);
  const v2Parts = v2.split('.').map(Number);
  
  for (let i = 0; i < Math.max(v1Parts.length, v2Parts.length); i++) {
    const v1Part = v1Parts[i] || 0;
    const v2Part = v2Parts[i] || 0;
    if (v1Part > v2Part) return 1;
    if (v1Part < v2Part) return -1;
  }
  return 0;
}

// Add the get computer by serial tool using the correct server.tool format
server.tool(
  'getComputerBySerial',
  {
    serialNumber: z.string().describe('Computer serial number'),
    username: z.string().describe('Jamf Pro username'),
    password: z.string().describe('Jamf Pro password'),
  },
  async ({ serialNumber, username, password }) => {
    try {
      // Get computer details
      const computerInfo = await getComputerBySerial(serialNumber);
      
      // Create a summary of the computer's details
      const summary = {
        id: computerInfo.id || 'Unknown',
        name: computerInfo.general?.name || 'Unknown',
        serialNumber: computerInfo.hardware?.serialNumber || 'Unknown',
        model: computerInfo.hardware?.model || 'Unknown',
        modelIdentifier: computerInfo.hardware?.modelIdentifier || 'Unknown',
        processor: computerInfo.hardware?.processor || 'Unknown',
        memory: computerInfo.hardware?.totalRamMegabytes ? `${Math.round(computerInfo.hardware.totalRamMegabytes/1024)} GB` : 'Unknown',
        macOS: {
          version: computerInfo.operatingSystem?.version || 'Unknown',
          build: computerInfo.operatingSystem?.build || 'Unknown',
        },
        fileVault: {
          status: computerInfo.operatingSystem?.fileVault2Status || computerInfo.diskEncryption?.fileVault2Status || 'Unknown',
          encrypted: computerInfo.diskEncryption?.bootPartitionEncryptionEnabled === true ? 'Yes' : 'No',
        },
        user: {
          username: computerInfo.userAndLocation?.username || 'Unknown',
          realName: computerInfo.userAndLocation?.realname || 'Unknown',
          email: computerInfo.userAndLocation?.email || 'Unknown',
          position: computerInfo.userAndLocation?.position || 'Unknown',
        }
      };
      
      // Format as text for MCP compliance
      const result = JSON.stringify(summary, null, 2);
      
      return {
        content: [
          {
            type: 'text',
            text: result,
          },
        ],
      };
    } catch (error) {
      console.error('Error:', error);
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${error.message || 'Failed to get computer details'}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// Add the get computer by ID tool using the correct server.tool format
server.tool(
  'getComputerById',
  {
    id: z.string().describe('Computer ID'),
    username: z.string().describe('Jamf Pro username'),
    password: z.string().describe('Jamf Pro password'),
  },
  async ({ id, username, password }) => {
    try {
      // Get computer details
      const computerInfo = await getComputerById(id);
      
      if (computerInfo.error) {
        throw new Error(computerInfo.error);
      }

      // Create a comprehensive summary of the computer's details
      const summary = {
        id: computerInfo.id || 'Unknown',
        udid: computerInfo.udid || 'Unknown',
        name: computerInfo.general?.name || 'Unknown',
        
        // General Information
        general: {
          lastIpAddress: computerInfo.general?.lastIpAddress || 'Unknown',
          lastReportedIp: computerInfo.general?.lastReportedIp || 'Unknown',
          jamfVersion: computerInfo.general?.jamfBinaryVersion || 'Unknown',
          platform: computerInfo.general?.platform || 'Unknown',
          supervised: computerInfo.general?.supervised || false,
          mdmCapable: computerInfo.general?.mdmCapable?.capable || false,
          lastContactTime: computerInfo.general?.lastContactTime || 'Unknown',
          lastEnrolledDate: computerInfo.general?.lastEnrolledDate || 'Unknown',
          reportDate: computerInfo.general?.reportDate || 'Unknown',
          enrollmentMethod: computerInfo.general?.enrollmentMethod?.objectName || 'Unknown',
          mdmProfileExpiration: computerInfo.general?.mdmProfileExpiration || 'Unknown',
          userApprovedMdm: computerInfo.general?.userApprovedMdm || false,
          site: computerInfo.general?.site?.name || 'Unknown'
        },
        
        // Hardware Information
        hardware: {
          model: computerInfo.hardware?.model || 'Unknown',
          modelIdentifier: computerInfo.hardware?.modelIdentifier || 'Unknown',
          processor: computerInfo.hardware?.processor || 'Unknown',
          processorSpeedMhz: computerInfo.hardware?.processorSpeedMhz || 'Unknown',
          processorCount: computerInfo.hardware?.processorCount || 'Unknown',
          coreCount: computerInfo.hardware?.coreCount || 'Unknown',
          memory: computerInfo.hardware?.totalRamMegabytes ? `${Math.round(computerInfo.hardware.totalRamMegabytes/1024)} GB` : 'Unknown',
          serialNumber: computerInfo.hardware?.serialNumber || 'Unknown',
          macAddress: computerInfo.hardware?.macAddress || 'Unknown',
          bluetoothMacAddress: computerInfo.hardware?.bluetoothMacAddress || 'Unknown',
          thermalPressure: computerInfo.hardware?.thermalPressure || 'Unknown'
        },
        
        // Operating System Information
        operatingSystem: {
          version: computerInfo.operatingSystem?.version || 'Unknown',
          build: computerInfo.operatingSystem?.build || 'Unknown',
          name: computerInfo.operatingSystem?.name || 'Unknown',
          activeDirectoryStatus: computerInfo.operatingSystem?.activeDirectoryStatus || 'Unknown',
          fileVault2Status: computerInfo.operatingSystem?.fileVault2Status || 'Unknown',
          softwareUpdateDeviceId: computerInfo.operatingSystem?.softwareUpdateDeviceId || 'Unknown'
        },
        
        // Security Information
        security: {
          sipStatus: computerInfo.security?.systemIntegrityProtectionStatus || 'Unknown',
          gatekeeperStatus: computerInfo.security?.gatekeeperStatus || 'Unknown',
          xprotectVersion: computerInfo.security?.xprotectVersion || 'Unknown',
          autoLoginDisabled: computerInfo.security?.autoLoginDisabled || false,
          remoteDesktopEnabled: computerInfo.security?.remoteDesktopEnabled || false,
          activationLockEnabled: computerInfo.security?.activationLockEnabled || false
        },
        
        // Storage Information
        storage: computerInfo.storage?.disks?.map(disk => ({
          device: disk.device || 'Unknown',
          model: disk.model || 'Unknown',
          revision: disk.revision || 'Unknown',
          serialNumber: disk.serialNumber || 'Unknown',
          sizeMegabytes: disk.sizeMegabytes || 'Unknown',
          smart: disk.smartStatus || 'Unknown',
          type: disk.type || 'Unknown',
          partitions: disk.partitions?.map(partition => ({
            name: partition.name || 'Unknown',
            sizeMegabytes: partition.sizeMegabytes || 'Unknown',
            availableMegabytes: partition.availableMegabytes || 'Unknown',
            percentUsed: partition.percentUsed || 'Unknown',
            fileVault2State: partition.fileVault2State || 'Unknown',
            fileVault2Progress: partition.fileVault2Progress || 'Unknown'
          }))
        })) || [],
        
        // User and Location Information
        user: {
          username: computerInfo.userAndLocation?.username || 'Unknown',
          realName: computerInfo.userAndLocation?.realname || 'Unknown',
          email: computerInfo.userAndLocation?.email || 'Unknown',
          position: computerInfo.userAndLocation?.position || 'Unknown',
          phone: computerInfo.userAndLocation?.phone || 'Unknown',
          department: computerInfo.userAndLocation?.department || 'Unknown',
          building: computerInfo.userAndLocation?.building || 'Unknown',
          room: computerInfo.userAndLocation?.room || 'Unknown'
        },
        
        // Group Memberships
        groups: computerInfo.groupMemberships?.map(group => ({
          id: group.id || 'Unknown',
          name: group.name || 'Unknown',
          smartGroup: group.smartGroup || false
        })) || [],
        
        // Configuration Profiles
        configurationProfiles: computerInfo.configurationProfiles?.map(profile => ({
          id: profile.id || 'Unknown',
          name: profile.name || 'Unknown',
          uuid: profile.uuid || 'Unknown',
          isRemovable: profile.isRemovable || false
        })) || [],
        
        // Local User Accounts
        localUserAccounts: computerInfo.localUserAccounts?.map(account => ({
          uid: account.uid || 'Unknown',
          username: account.username || 'Unknown',
          fullName: account.fullName || 'Unknown',
          admin: account.admin || false,
          homeDirectory: account.homeDirectory || 'Unknown',
          homeDirectorySizeMb: account.homeDirectorySizeMb || 'Unknown',
          filevaultEnabled: account.filevaultEnabled || false
        })) || []
      };
      
      // Format as text for MCP compliance
      const result = JSON.stringify(summary, null, 2);
      
      return {
        content: [
          {
            type: 'text',
            text: result,
          },
        ],
      };
    } catch (error) {
      console.error('Error getting computer by ID:', error.message);
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${error.message || 'Failed to get computer information'}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// Add the list computers tool using the correct server.tool format
server.tool(
  'listComputers',
  {
    username: z.string().describe('Jamf Pro username'),
    password: z.string().describe('Jamf Pro password'),
    limit: z.number().optional().describe('Number of computers to return (default: 10)'),
    modelFilter: z.string().optional().describe('Filter by model (e.g., "MacBook Air")'),
    managedOnly: z.boolean().optional().describe('Only return managed devices')
  },
  async ({ username, password, limit = 10, modelFilter, managedOnly = false }) => {
    try {
      const computerList = await listComputers(username, password, limit, modelFilter, managedOnly);
      
      // Format as text for MCP compliance
      const result = JSON.stringify(computerList, null, 2);
      
      return {
        content: [
          {
            type: 'text',
            text: result,
          },
        ],
      };
    } catch (error) {
      console.error('Error listing computers:', error.message);
      if (error.response) {
        console.error('Response status:', error.response.status);
        console.error('Response data:', JSON.stringify(error.response.data, null, 2).substring(0, 500));
      }
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${error.message || 'Failed to list computers'}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// Add the management counts tool
server.tool(
  'getManagementCounts',
  {
    username: z.string().describe('Jamf Pro username'),
    password: z.string().describe('Jamf Pro password'),
  },
  async ({ username, password }) => {
    try {
      // Get token
      const token = await getJamfToken(username, password);
      
      // Initialize counts
      let managed = 0;
      let unmanaged = 0;
      let page = 0;
      const pageSize = 100;
      let hasMore = true;
      
      // Paginate through all computers
      while (hasMore) {
        const url = `${JAMF_API_BASE_URL}/v1/computers-inventory?page=${page}&page-size=${pageSize}&section=GENERAL`;
        const response = await axios.get(url, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/json'
          }
        });
        
        // Count managed/unmanaged computers
        response.data.results.forEach(computer => {
          if (computer.general?.remoteManagement?.managed) {
            managed++;
          } else {
            unmanaged++;
          }
        });
        
        // Check if there are more pages
        hasMore = response.data.totalCount > (page + 1) * pageSize;
        page++;
      }
      
      // Format the results as text for MCP compliance
      const summary = {
        managed,
        unmanaged,
        total: managed + unmanaged
      };
      
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(summary, null, 2)
          }
        ]
      };
      
    } catch (error) {
      console.error('Error getting management counts:', error.message);
      if (error.response) {
        console.error('Response status:', error.response.status);
        console.error('Response data:', JSON.stringify(error.response.data, null, 2).substring(0, 500));
      }
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${error.message || 'Failed to get management counts'}`
          }
        ],
        isError: true
      };
    }
  }
);

// Add the extension attributes tool
server.tool(
  'getExtensionAttributes',
  {
    id: z.string().optional().describe('Computer ID (optional)'),
    serialNumber: z.string().optional().describe('Computer serial number (optional)'),
    username: z.string().describe('Jamf Pro username'),
    password: z.string().describe('Jamf Pro password'),
  },
  async ({ id, serialNumber, username, password }) => {
    try {
      let computerId = id;
      
      // If serial number is provided but no ID, get the ID first
      if (!computerId && serialNumber) {
        const computerInfo = await getComputerBySerial(serialNumber);
        if (computerInfo.error) {
          throw new Error(computerInfo.error);
        }
        computerId = computerInfo.id;
      }
      
      if (!computerId) {
        throw new Error('Either computer ID or serial number must be provided');
      }
      
      // Get extension attributes
      const result = await getExtensionAttributes(computerId, username, password);
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      // Format as text for MCP compliance
      const formattedResult = JSON.stringify(result, null, 2);
      
      return {
        content: [
          {
            type: 'text',
            text: formattedResult,
          },
        ],
      };
    } catch (error) {
      console.error('Error:', error);
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${error.message || 'Failed to get extension attributes'}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// Add the get computers by user tool
server.tool(
  'getComputersByUser',
  {
    userIdentifier: z.string().describe('User identifier (firstname.lastname, email, or name)'),
    username: z.string().describe('Jamf Pro username'),
    password: z.string().describe('Jamf Pro password'),
  },
  async ({ userIdentifier, username, password }) => {
    try {
      const computers = await getComputersByUser(userIdentifier, username, password);
      
      if (computers.error) {
        throw new Error(computers.error);
      }

      // Format the results
      const formattedComputers = computers.map(computer => ({
        id: computer.id || 'Unknown',
        name: computer.general?.name || 'Unknown',
        serialNumber: computer.hardware?.serialNumber || 'Unknown',
        model: computer.hardware?.model || 'Unknown',
        user: {
          username: computer.userAndLocation?.username || 'Unknown',
          realName: computer.userAndLocation?.realname || 'Unknown',
          email: computer.userAndLocation?.email || 'Unknown',
          position: computer.userAndLocation?.position || 'Unknown'
        },
        lastContactTime: computer.general?.lastContactTime || 'Unknown',
        managed: computer.general?.remoteManagement?.managed || false,
        osVersion: computer.operatingSystem?.version || 'Unknown'
      }));

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(formattedComputers, null, 2),
          },
        ],
      };
    } catch (error) {
      console.error('Error:', error);
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${error.message || 'Failed to get computers by user'}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// Add the security status tool
server.tool(
  'getSecurityStatus',
  {
    identifier: z.string().describe('Device ID or serial number'),
    username: z.string().describe('Jamf Pro username'),
    password: z.string().describe('Jamf Pro password'),
  },
  async ({ identifier, username, password }) => {
    try {
      const securityStatus = await getSecurityStatus(identifier, username, password);
      
      if (securityStatus.error) {
        throw new Error(securityStatus.error);
      }

      // Format as text for MCP compliance
      const result = JSON.stringify(securityStatus, null, 2);
      
      return {
        content: [
          {
            type: 'text',
            text: result,
          },
        ],
      };
    } catch (error) {
      console.error('Error:', error);
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${error.message || 'Failed to get security status'}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// Start the server
const transport = new StdioServerTransport();
server.connect(transport).catch((error) => {
  console.error('[MCP Error]', error);
  process.exit(1);
});

console.error('Jamf MCP server running on stdio');

// Export the functions for use in other files
export { getComputerBySerial, getComputerById, getComputerDetails, getExtensionAttributes, listComputers }; 