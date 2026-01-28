# 🧪 RECIPE TEMPLATES FOR NEW SECURITY CHECKS

> **Production-Ready Recipe Templates**
> 
> Generated: 2026-01-04
> 
> These templates are based on the existing recipe patterns in `huskeys-web-apps/packages/api/findings-engine/src/recipes/`
> and target the high-value unused tables identified in our schema analysis.

---

## Quick Reference: Recipe Structure

Every recipe consists of these files:

```
recipes/
└── {vendor}/
    └── {recipe-name}/
        ├── {recipe-name}.recipe.ts          # Main recipe class
        ├── {recipe-name}.repository.ts      # Database queries
        ├── {recipe-name}.types.ts           # TypeScript types
        └── index.ts                         # Exports
```

---

## Template 1: Cloudflare Bot Management Not in Fight Mode

### `cloudflare/cf-bot-management-weak/cf-bot-management-weak.types.ts`

```typescript
export interface CfBotManagementWeakRow {
  id: string;
  zoneName: string;
  zoneCfId: string;
  fightMode: boolean;
  enableJs: boolean;
  aiBotProtection: string | null;
  sbfmDefinitelyAutomated: string | null;
  sbfmLikelyAutomated: string | null;
  sbfmVerifiedBots: string | null;
  usingLatestModel: boolean;
  orgId: string;
  orgName: string;
}

export interface CfBotManagementWeakFinding {
  zoneId: string;
  zoneName: string;
  zoneCfId: string;
  issues: string[];
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  recommendation: string;
}
```

### `cloudflare/cf-bot-management-weak/cf-bot-management-weak.repository.ts`

```typescript
import { CloudflareBotManagementTable } from '@huskeys/common-api-models/src/models/cloudflare-raw/bot-management/bot-management.model';
import { CloudflareZoneTable } from '@huskeys/common-api-models/src/models/cloudflare-raw/zone/cloudflare-zone.model';
import { and, eq, or, sql } from 'drizzle-orm';
import { CfBotManagementWeakRow } from './cf-bot-management-weak.types';

export class CfBotManagementWeakRepository {
  constructor(private readonly db: any) {}

  async getWeakBotManagementZones(): Promise<CfBotManagementWeakRow[]> {
    return await this.db
      .select({
        id: CloudflareBotManagementTable.id,
        zoneName: CloudflareZoneTable.name,
        zoneCfId: CloudflareZoneTable.cfId,
        fightMode: CloudflareBotManagementTable.fightMode,
        enableJs: CloudflareBotManagementTable.enableJs,
        aiBotProtection: CloudflareBotManagementTable.aiBotProtection,
        sbfmDefinitelyAutomated: CloudflareBotManagementTable.sbfmDefinitelyAutomated,
        sbfmLikelyAutomated: CloudflareBotManagementTable.sbfmLikelyAutomated,
        sbfmVerifiedBots: CloudflareBotManagementTable.sbfmVerifiedBots,
        usingLatestModel: CloudflareBotManagementTable.usingLatestModel,
        orgId: CloudflareZoneTable.orgId,
        orgName: CloudflareZoneTable.orgName,
      })
      .from(CloudflareBotManagementTable)
      .innerJoin(CloudflareZoneTable, eq(CloudflareZoneTable.id, CloudflareBotManagementTable.zoneId))
      .where(
        and(
          eq(CloudflareZoneTable.isDeleted, false),
          eq(CloudflareZoneTable.status, 'active'),
          eq(CloudflareZoneTable.paused, false),
          eq(CloudflareBotManagementTable.isDeleted, false),
          or(
            eq(CloudflareBotManagementTable.fightMode, false),
            eq(CloudflareBotManagementTable.enableJs, false),
            sql`${CloudflareBotManagementTable.sbfmDefinitelyAutomated} NOT IN ('BLOCK', 'MANAGED_CHALLENGE')`,
            eq(CloudflareBotManagementTable.sbfmLikelyAutomated, 'ALLOW'),
          ),
        ),
      )
      .orderBy(CloudflareZoneTable.orgName, CloudflareZoneTable.name);
  }
}
```

### `cloudflare/cf-bot-management-weak/cf-bot-management-weak.recipe.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { BaseFindingRecipe } from '../../base-finding-recipe';
import { RecipeMetadata } from '../../recipe.types';
import { CfBotManagementWeakRepository } from './cf-bot-management-weak.repository';
import { CfBotManagementWeakRow, CfBotManagementWeakFinding } from './cf-bot-management-weak.types';

@Injectable()
export class CfBotManagementWeakRecipe extends BaseFindingRecipe<CfBotManagementWeakRow, CfBotManagementWeakFinding> {
  static readonly metadata: RecipeMetadata = {
    id: 'cf-bot-management-weak',
    name: 'Cloudflare Bot Management Not in Fight Mode',
    description: 'Identifies zones where bot management is not properly configured to actively block bots',
    vendor: 'cloudflare',
    severity: 'CRITICAL',
    category: 'bot-protection',
    documentation: 'https://developers.cloudflare.com/bots/get-started/bm-subscription/',
  };

  constructor(private readonly repository: CfBotManagementWeakRepository) {
    super();
  }

  async fetchData(): Promise<CfBotManagementWeakRow[]> {
    return this.repository.getWeakBotManagementZones();
  }

  transformToFindings(rows: CfBotManagementWeakRow[]): CfBotManagementWeakFinding[] {
    return rows.map((row) => {
      const issues: string[] = [];
      
      if (!row.fightMode) {
        issues.push('Fight mode is disabled - bots are not actively challenged');
      }
      if (!row.enableJs) {
        issues.push('JavaScript detection is disabled - cannot detect headless browsers');
      }
      if (row.sbfmDefinitelyAutomated && !['BLOCK', 'MANAGED_CHALLENGE'].includes(row.sbfmDefinitelyAutomated)) {
        issues.push(`Definitely automated bots set to ${row.sbfmDefinitelyAutomated} instead of BLOCK`);
      }
      if (row.sbfmLikelyAutomated === 'ALLOW') {
        issues.push('Likely automated bots are being allowed through');
      }
      if (!row.usingLatestModel) {
        issues.push('Not using latest bot detection model');
      }

      const severity = issues.some(i => i.includes('Fight mode') || i.includes('BLOCK')) 
        ? 'CRITICAL' 
        : issues.length > 2 ? 'HIGH' : 'MEDIUM';

      return {
        zoneId: row.id,
        zoneName: row.zoneName,
        zoneCfId: row.zoneCfId,
        issues,
        severity,
        recommendation: 'Enable fight mode, JavaScript detection, and set automated bot actions to BLOCK or MANAGED_CHALLENGE',
      };
    });
  }

  getDeduplicationKey(finding: CfBotManagementWeakFinding): string {
    return `cf-bot-weak:${finding.zoneCfId}`;
  }
}
```

---

## Template 2: AWS WAF Logging Not Configured

### `aws/aws-waf-no-logging/aws-waf-no-logging.types.ts`

```typescript
export interface AwsWafNoLoggingRow {
  id: string;
  aclName: string;
  aclArn: string;
  region: string;
  defaultAction: string;
  capacity: number;
  awsAccountId: string;
  loggingConfigId: string | null;
  logDestination: string | null;
  logScope: string | null;
  orgId: string;
  orgName: string;
}

export interface AwsWafNoLoggingFinding {
  aclId: string;
  aclName: string;
  aclArn: string;
  region: string;
  loggingStatus: 'NONE' | 'PARTIAL' | 'CONFIGURED';
  issues: string[];
  severity: 'CRITICAL' | 'HIGH';
  recommendation: string;
}
```

### `aws/aws-waf-no-logging/aws-waf-no-logging.repository.ts`

```typescript
import { WafAclTable } from '@huskeys/common-api-models/src/models/aws-raw/waf/acl/waf-acl.model';
import { WafAclLoggingConfigTable } from '@huskeys/common-api-models/src/models/aws-raw/waf/acl-logging-config/acl-logging-config.model';
import { and, eq, isNull, or, sql } from 'drizzle-orm';
import { AwsWafNoLoggingRow } from './aws-waf-no-logging.types';

export class AwsWafNoLoggingRepository {
  constructor(private readonly db: any) {}

  async getWafAclsWithoutLogging(): Promise<AwsWafNoLoggingRow[]> {
    return await this.db
      .select({
        id: WafAclTable.id,
        aclName: WafAclTable.name,
        aclArn: WafAclTable.arn,
        region: WafAclTable.region,
        defaultAction: WafAclTable.defaultAction,
        capacity: WafAclTable.capacity,
        awsAccountId: WafAclTable.awsAccountId,
        loggingConfigId: WafAclLoggingConfigTable.id,
        logDestination: WafAclLoggingConfigTable.logDestinationConfig,
        logScope: WafAclLoggingConfigTable.logScope,
        orgId: WafAclTable.organizationId,
        orgName: WafAclTable.organizationName,
      })
      .from(WafAclTable)
      .leftJoin(
        WafAclLoggingConfigTable,
        and(
          eq(WafAclLoggingConfigTable.wafAclId, WafAclTable.id),
          eq(WafAclLoggingConfigTable.isDeleted, false),
        ),
      )
      .where(
        and(
          eq(WafAclTable.isDeleted, false),
          or(
            isNull(WafAclLoggingConfigTable.id),
            sql`${WafAclLoggingConfigTable.logScope} != 'ALL'`,
          ),
        ),
      )
      .orderBy(WafAclTable.organizationName, WafAclTable.name);
  }
}
```

### `aws/aws-waf-no-logging/aws-waf-no-logging.recipe.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { BaseFindingRecipe } from '../../base-finding-recipe';
import { RecipeMetadata } from '../../recipe.types';
import { AwsWafNoLoggingRepository } from './aws-waf-no-logging.repository';
import { AwsWafNoLoggingRow, AwsWafNoLoggingFinding } from './aws-waf-no-logging.types';

@Injectable()
export class AwsWafNoLoggingRecipe extends BaseFindingRecipe<AwsWafNoLoggingRow, AwsWafNoLoggingFinding> {
  static readonly metadata: RecipeMetadata = {
    id: 'aws-waf-no-logging',
    name: 'AWS WAF Logging Not Configured',
    description: 'Identifies WAF ACLs without logging or with incomplete logging configuration',
    vendor: 'aws',
    severity: 'CRITICAL',
    category: 'visibility',
    documentation: 'https://docs.aws.amazon.com/waf/latest/developerguide/logging.html',
  };

  constructor(private readonly repository: AwsWafNoLoggingRepository) {
    super();
  }

  async fetchData(): Promise<AwsWafNoLoggingRow[]> {
    return this.repository.getWafAclsWithoutLogging();
  }

  transformToFindings(rows: AwsWafNoLoggingRow[]): AwsWafNoLoggingFinding[] {
    return rows.map((row) => {
      const issues: string[] = [];
      let loggingStatus: 'NONE' | 'PARTIAL' | 'CONFIGURED' = 'CONFIGURED';

      if (!row.loggingConfigId) {
        issues.push('No logging configuration found');
        loggingStatus = 'NONE';
      } else if (row.logScope !== 'ALL') {
        issues.push(`Logging scope is ${row.logScope || 'undefined'} instead of ALL`);
        loggingStatus = 'PARTIAL';
      }

      if (!row.logDestination) {
        issues.push('No log destination configured');
      }

      return {
        aclId: row.id,
        aclName: row.aclName,
        aclArn: row.aclArn,
        region: row.region,
        loggingStatus,
        issues,
        severity: loggingStatus === 'NONE' ? 'CRITICAL' : 'HIGH',
        recommendation: 'Configure WAF logging with log_scope=ALL and ship logs to S3, CloudWatch, or Kinesis',
      };
    });
  }

  getDeduplicationKey(finding: AwsWafNoLoggingFinding): string {
    return `aws-waf-no-logging:${finding.aclArn}`;
  }
}
```

---

## Template 3: AWS Managed Rules Overridden to COUNT

### `aws/aws-managed-rules-count-override/aws-managed-rules-count-override.types.ts`

```typescript
export interface AwsManagedRulesCountOverrideRow {
  id: string;
  aclName: string;
  aclArn: string;
  region: string;
  managedRuleGroupName: string;
  ruleName: string;
  overrideAction: string;
  awsAccountId: string;
  orgId: string;
  orgName: string;
}

export interface AwsManagedRulesCountOverrideFinding {
  aclId: string;
  aclName: string;
  aclArn: string;
  region: string;
  overriddenRules: Array<{
    managedRuleGroupName: string;
    ruleName: string;
    overrideAction: string;
  }>;
  totalOverrides: number;
  severity: 'CRITICAL' | 'HIGH';
  recommendation: string;
}
```

### `aws/aws-managed-rules-count-override/aws-managed-rules-count-override.repository.ts`

```typescript
import { WafAclTable } from '@huskeys/common-api-models/src/models/aws-raw/waf/acl/waf-acl.model';
import { AclManagedRuleGroupRuleOverrideTable } from '@huskeys/common-api-models/src/models/aws-raw/waf/acl-managed-rule-override/acl-managed-rule-override.model';
import { and, eq } from 'drizzle-orm';
import { AwsManagedRulesCountOverrideRow } from './aws-managed-rules-count-override.types';

export class AwsManagedRulesCountOverrideRepository {
  constructor(private readonly db: any) {}

  async getOverriddenManagedRules(): Promise<AwsManagedRulesCountOverrideRow[]> {
    return await this.db
      .select({
        id: AclManagedRuleGroupRuleOverrideTable.id,
        aclName: WafAclTable.name,
        aclArn: WafAclTable.arn,
        region: WafAclTable.region,
        managedRuleGroupName: AclManagedRuleGroupRuleOverrideTable.managedRuleGroupName,
        ruleName: AclManagedRuleGroupRuleOverrideTable.ruleName,
        overrideAction: AclManagedRuleGroupRuleOverrideTable.overrideAction,
        awsAccountId: WafAclTable.awsAccountId,
        orgId: WafAclTable.organizationId,
        orgName: WafAclTable.organizationName,
      })
      .from(AclManagedRuleGroupRuleOverrideTable)
      .innerJoin(WafAclTable, eq(WafAclTable.id, AclManagedRuleGroupRuleOverrideTable.wafAclId))
      .where(
        and(
          eq(AclManagedRuleGroupRuleOverrideTable.isDeleted, false),
          eq(WafAclTable.isDeleted, false),
          eq(AclManagedRuleGroupRuleOverrideTable.overrideAction, 'COUNT'),
        ),
      )
      .orderBy(WafAclTable.organizationName, WafAclTable.name);
  }
}
```

### `aws/aws-managed-rules-count-override/aws-managed-rules-count-override.recipe.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { BaseFindingRecipe } from '../../base-finding-recipe';
import { RecipeMetadata } from '../../recipe.types';
import { AwsManagedRulesCountOverrideRepository } from './aws-managed-rules-count-override.repository';
import { AwsManagedRulesCountOverrideRow, AwsManagedRulesCountOverrideFinding } from './aws-managed-rules-count-override.types';

@Injectable()
export class AwsManagedRulesCountOverrideRecipe extends BaseFindingRecipe<AwsManagedRulesCountOverrideRow, AwsManagedRulesCountOverrideFinding> {
  static readonly metadata: RecipeMetadata = {
    id: 'aws-managed-rules-count-override',
    name: 'AWS Managed Rules Overridden to COUNT',
    description: 'Identifies managed rule group rules that have been overridden from BLOCK to COUNT mode',
    vendor: 'aws',
    severity: 'CRITICAL',
    category: 'waf-configuration',
    documentation: 'https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-managed-rule-group.html',
  };

  constructor(private readonly repository: AwsManagedRulesCountOverrideRepository) {
    super();
  }

  async fetchData(): Promise<AwsManagedRulesCountOverrideRow[]> {
    return this.repository.getOverriddenManagedRules();
  }

  transformToFindings(rows: AwsManagedRulesCountOverrideRow[]): AwsManagedRulesCountOverrideFinding[] {
    // Group by ACL
    const aclMap = new Map<string, AwsManagedRulesCountOverrideRow[]>();
    
    rows.forEach((row) => {
      const key = row.aclArn;
      if (!aclMap.has(key)) {
        aclMap.set(key, []);
      }
      aclMap.get(key)!.push(row);
    });

    return Array.from(aclMap.entries()).map(([aclArn, aclRows]) => {
      const firstRow = aclRows[0];
      const overriddenRules = aclRows.map((r) => ({
        managedRuleGroupName: r.managedRuleGroupName,
        ruleName: r.ruleName,
        overrideAction: r.overrideAction,
      }));

      return {
        aclId: firstRow.id,
        aclName: firstRow.aclName,
        aclArn: firstRow.aclArn,
        region: firstRow.region,
        overriddenRules,
        totalOverrides: overriddenRules.length,
        severity: overriddenRules.length > 5 ? 'CRITICAL' : 'HIGH',
        recommendation: 'Review overridden rules and re-enable blocking where possible. Use labels for monitoring instead of COUNT.',
      };
    });
  }

  getDeduplicationKey(finding: AwsManagedRulesCountOverrideFinding): string {
    return `aws-managed-count:${finding.aclArn}:${finding.totalOverrides}`;
  }
}
```

---

## Template 4: Azure WAF Exclusions Too Broad

### `azure/az-waf-broad-exclusions/az-waf-broad-exclusions.types.ts`

```typescript
export interface AzWafBroadExclusionsRow {
  id: string;
  wafPolicyName: string;
  wafPolicyId: string;
  mode: string;
  state: string;
  matchVariable: string;
  selectorMatchOperator: string;
  selector: string | null;
  resourceGroup: string;
  orgId: string;
}

export interface AzWafBroadExclusionsFinding {
  wafPolicyId: string;
  wafPolicyName: string;
  mode: string;
  exclusions: Array<{
    matchVariable: string;
    selectorMatchOperator: string;
    selector: string | null;
    riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  }>;
  totalExclusions: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  recommendation: string;
}
```

### `azure/az-waf-broad-exclusions/az-waf-broad-exclusions.repository.ts`

```typescript
import { AzureAppGatewayWafPoliciesTable } from '@huskeys/common-api-models/src/models/azure/app-gateway-waf-policies/app-gateway-waf-policies.model';
import { AzureAppGatewayWafManagedRuleExclusionsTable } from '@huskeys/common-api-models/src/models/azure/app-gateway-waf-exclusions/app-gateway-waf-exclusions.model';
import { AzureResourceGroupsTable } from '@huskeys/common-api-models/src/models/azure/resource-groups/resource-groups.model';
import { and, eq, isNull, or, sql } from 'drizzle-orm';
import { AzWafBroadExclusionsRow } from './az-waf-broad-exclusions.types';

export class AzWafBroadExclusionsRepository {
  constructor(private readonly db: any) {}

  async getBroadExclusions(): Promise<AzWafBroadExclusionsRow[]> {
    return await this.db
      .select({
        id: AzureAppGatewayWafManagedRuleExclusionsTable.id,
        wafPolicyName: AzureAppGatewayWafPoliciesTable.name,
        wafPolicyId: AzureAppGatewayWafPoliciesTable.id,
        mode: AzureAppGatewayWafPoliciesTable.mode,
        state: AzureAppGatewayWafPoliciesTable.state,
        matchVariable: AzureAppGatewayWafManagedRuleExclusionsTable.matchVariable,
        selectorMatchOperator: AzureAppGatewayWafManagedRuleExclusionsTable.selectorMatchOperator,
        selector: AzureAppGatewayWafManagedRuleExclusionsTable.selector,
        resourceGroup: AzureResourceGroupsTable.name,
        orgId: AzureAppGatewayWafPoliciesTable.organizationId,
      })
      .from(AzureAppGatewayWafManagedRuleExclusionsTable)
      .innerJoin(
        AzureAppGatewayWafPoliciesTable,
        eq(AzureAppGatewayWafPoliciesTable.id, AzureAppGatewayWafManagedRuleExclusionsTable.wafPolicyId),
      )
      .innerJoin(
        AzureResourceGroupsTable,
        eq(AzureResourceGroupsTable.id, AzureAppGatewayWafPoliciesTable.rgId),
      )
      .where(
        and(
          eq(AzureAppGatewayWafManagedRuleExclusionsTable.isDeleted, false),
          eq(AzureAppGatewayWafPoliciesTable.isDeleted, false),
          or(
            isNull(AzureAppGatewayWafManagedRuleExclusionsTable.selector),
            eq(AzureAppGatewayWafManagedRuleExclusionsTable.selector, ''),
            eq(AzureAppGatewayWafManagedRuleExclusionsTable.selector, '*'),
            and(
              eq(AzureAppGatewayWafManagedRuleExclusionsTable.selectorMatchOperator, 'CONTAINS'),
              sql`LENGTH(${AzureAppGatewayWafManagedRuleExclusionsTable.selector}) < 3`,
            ),
          ),
        ),
      )
      .orderBy(AzureAppGatewayWafPoliciesTable.organizationId, AzureAppGatewayWafPoliciesTable.name);
  }
}
```

### `azure/az-waf-broad-exclusions/az-waf-broad-exclusions.recipe.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { BaseFindingRecipe } from '../../base-finding-recipe';
import { RecipeMetadata } from '../../recipe.types';
import { AzWafBroadExclusionsRepository } from './az-waf-broad-exclusions.repository';
import { AzWafBroadExclusionsRow, AzWafBroadExclusionsFinding } from './az-waf-broad-exclusions.types';

@Injectable()
export class AzWafBroadExclusionsRecipe extends BaseFindingRecipe<AzWafBroadExclusionsRow, AzWafBroadExclusionsFinding> {
  static readonly metadata: RecipeMetadata = {
    id: 'az-waf-broad-exclusions',
    name: 'Azure WAF Exclusions Too Broad',
    description: 'Identifies WAF exclusions that are overly permissive and may allow attacks to bypass protection',
    vendor: 'azure',
    severity: 'CRITICAL',
    category: 'waf-configuration',
    documentation: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-configuration',
  };

  constructor(private readonly repository: AzWafBroadExclusionsRepository) {
    super();
  }

  async fetchData(): Promise<AzWafBroadExclusionsRow[]> {
    return this.repository.getBroadExclusions();
  }

  private assessRiskLevel(row: AzWafBroadExclusionsRow): 'CRITICAL' | 'HIGH' | 'MEDIUM' {
    if (!row.selector || row.selector === '' || row.selector === '*') {
      return 'CRITICAL';
    }
    if (row.selectorMatchOperator === 'CONTAINS' && row.selector.length < 3) {
      return 'HIGH';
    }
    return 'MEDIUM';
  }

  transformToFindings(rows: AzWafBroadExclusionsRow[]): AzWafBroadExclusionsFinding[] {
    // Group by WAF policy
    const policyMap = new Map<string, AzWafBroadExclusionsRow[]>();
    
    rows.forEach((row) => {
      const key = row.wafPolicyId;
      if (!policyMap.has(key)) {
        policyMap.set(key, []);
      }
      policyMap.get(key)!.push(row);
    });

    return Array.from(policyMap.entries()).map(([policyId, policyRows]) => {
      const firstRow = policyRows[0];
      const exclusions = policyRows.map((r) => ({
        matchVariable: r.matchVariable,
        selectorMatchOperator: r.selectorMatchOperator,
        selector: r.selector,
        riskLevel: this.assessRiskLevel(r),
      }));

      const hasCritical = exclusions.some((e) => e.riskLevel === 'CRITICAL');
      const hasHigh = exclusions.some((e) => e.riskLevel === 'HIGH');

      return {
        wafPolicyId: policyId,
        wafPolicyName: firstRow.wafPolicyName,
        mode: firstRow.mode,
        exclusions,
        totalExclusions: exclusions.length,
        severity: hasCritical ? 'CRITICAL' : hasHigh ? 'HIGH' : 'MEDIUM',
        recommendation: 'Replace wildcard exclusions with specific field names. Use exact match operators where possible.',
      };
    });
  }

  getDeduplicationKey(finding: AzWafBroadExclusionsFinding): string {
    return `az-waf-exclusions:${finding.wafPolicyId}:${finding.totalExclusions}`;
  }
}
```

---

## Template 5: Akamai Bot Categories Not Blocking

### `akamai/akamai-bot-categories-weak/akamai-bot-categories-weak.types.ts`

```typescript
export interface AkamaiBotCategoriesWeakRow {
  id: string;
  securityPolicyName: string;
  policyAkamaiId: string;
  botCategoryName: string;
  categoryDescription: string;
  currentAction: string;
  securityConfigName: string;
  orgId: string;
  orgName: string;
}

export interface AkamaiBotCategoriesWeakFinding {
  securityConfigName: string;
  securityPolicyName: string;
  policyAkamaiId: string;
  weakCategories: Array<{
    categoryName: string;
    description: string;
    currentAction: string;
    riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  }>;
  totalWeakCategories: number;
  severity: 'CRITICAL' | 'HIGH';
  recommendation: string;
}
```

### `akamai/akamai-bot-categories-weak/akamai-bot-categories-weak.repository.ts`

```typescript
import { AkamaiRawBotCategoryActionsTable } from '@huskeys/common-api-models/src/models/akamai-raw/bot-category-actions/bot-category-actions.model';
import { AkamaiRawSecurityPolicyTable } from '@huskeys/common-api-models/src/models/akamai-raw/security-policy/security-policy.model';
import { AkamaiRawSecurityConfigurationVersionTable } from '@huskeys/common-api-models/src/models/akamai-raw/security-configuration-version/security-configuration-version.model';
import { AkamaiRawSecurityConfigurationTable } from '@huskeys/common-api-models/src/models/akamai-raw/security-configuration/security-configuration.model';
import { AkamaiRawBotCategoriesTable } from '@huskeys/common-api-models/src/models/akamai-raw/bot-categories/bot-categories.model';
import { and, eq, inArray, isNull, or } from 'drizzle-orm';
import { AkamaiBotCategoriesWeakRow } from './akamai-bot-categories-weak.types';

export class AkamaiBotCategoriesWeakRepository {
  constructor(private readonly db: any) {}

  async getWeakBotCategories(): Promise<AkamaiBotCategoriesWeakRow[]> {
    return await this.db
      .select({
        id: AkamaiRawBotCategoryActionsTable.id,
        securityPolicyName: AkamaiRawSecurityPolicyTable.name,
        policyAkamaiId: AkamaiRawSecurityPolicyTable.akamaiId,
        botCategoryName: AkamaiRawBotCategoriesTable.name,
        categoryDescription: AkamaiRawBotCategoriesTable.description,
        currentAction: AkamaiRawBotCategoryActionsTable.action,
        securityConfigName: AkamaiRawSecurityConfigurationTable.name,
        orgId: AkamaiRawSecurityConfigurationTable.organizationId,
        orgName: AkamaiRawSecurityConfigurationTable.organizationName,
      })
      .from(AkamaiRawBotCategoryActionsTable)
      .innerJoin(
        AkamaiRawSecurityPolicyTable,
        eq(AkamaiRawSecurityPolicyTable.id, AkamaiRawBotCategoryActionsTable.securityPolicyId),
      )
      .innerJoin(
        AkamaiRawSecurityConfigurationVersionTable,
        eq(AkamaiRawSecurityConfigurationVersionTable.id, AkamaiRawSecurityPolicyTable.configVersionId),
      )
      .innerJoin(
        AkamaiRawSecurityConfigurationTable,
        eq(AkamaiRawSecurityConfigurationTable.id, AkamaiRawSecurityConfigurationVersionTable.configId),
      )
      .innerJoin(
        AkamaiRawBotCategoriesTable,
        eq(AkamaiRawBotCategoriesTable.id, AkamaiRawBotCategoryActionsTable.categoryId),
      )
      .where(
        and(
          eq(AkamaiRawBotCategoryActionsTable.isDeleted, false),
          eq(AkamaiRawSecurityPolicyTable.isDeleted, false),
          eq(AkamaiRawSecurityConfigurationTable.isDeleted, false),
          eq(AkamaiRawBotCategoriesTable.isDeleted, false),
          eq(AkamaiRawSecurityPolicyTable.applyBotmanControls, true),
          or(
            inArray(AkamaiRawBotCategoryActionsTable.action, ['MONITOR', 'ALLOW']),
            isNull(AkamaiRawBotCategoryActionsTable.action),
          ),
        ),
      )
      .orderBy(
        AkamaiRawSecurityConfigurationTable.organizationName,
        AkamaiRawSecurityConfigurationTable.name,
        AkamaiRawSecurityPolicyTable.name,
      );
  }
}
```

### `akamai/akamai-bot-categories-weak/akamai-bot-categories-weak.recipe.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { BaseFindingRecipe } from '../../base-finding-recipe';
import { RecipeMetadata } from '../../recipe.types';
import { AkamaiBotCategoriesWeakRepository } from './akamai-bot-categories-weak.repository';
import { AkamaiBotCategoriesWeakRow, AkamaiBotCategoriesWeakFinding } from './akamai-bot-categories-weak.types';

@Injectable()
export class AkamaiBotCategoriesWeakRecipe extends BaseFindingRecipe<AkamaiBotCategoriesWeakRow, AkamaiBotCategoriesWeakFinding> {
  static readonly metadata: RecipeMetadata = {
    id: 'akamai-bot-categories-weak',
    name: 'Akamai Bot Categories Not Blocking',
    description: 'Identifies security policies where bot categories are not configured to actively block malicious bots',
    vendor: 'akamai',
    severity: 'CRITICAL',
    category: 'bot-protection',
    documentation: 'https://techdocs.akamai.com/bot-manager/docs/bot-categories',
  };

  constructor(private readonly repository: AkamaiBotCategoriesWeakRepository) {
    super();
  }

  async fetchData(): Promise<AkamaiBotCategoriesWeakRow[]> {
    return this.repository.getWeakBotCategories();
  }

  private assessRiskLevel(categoryName: string, action: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' {
    const lowerName = categoryName.toLowerCase();
    
    if (action === 'ALLOW') {
      if (lowerName.includes('malicious') || lowerName.includes('impersonator')) {
        return 'CRITICAL';
      }
      return 'HIGH';
    }
    
    if (action === 'MONITOR') {
      if (lowerName.includes('malicious') || lowerName.includes('impersonator')) {
        return 'CRITICAL';
      }
      if (lowerName.includes('scraper') || lowerName.includes('spam')) {
        return 'HIGH';
      }
    }
    
    return 'MEDIUM';
  }

  transformToFindings(rows: AkamaiBotCategoriesWeakRow[]): AkamaiBotCategoriesWeakFinding[] {
    // Group by security policy
    const policyMap = new Map<string, AkamaiBotCategoriesWeakRow[]>();
    
    rows.forEach((row) => {
      const key = `${row.securityConfigName}:${row.policyAkamaiId}`;
      if (!policyMap.has(key)) {
        policyMap.set(key, []);
      }
      policyMap.get(key)!.push(row);
    });

    return Array.from(policyMap.entries()).map(([key, policyRows]) => {
      const firstRow = policyRows[0];
      const weakCategories = policyRows.map((r) => ({
        categoryName: r.botCategoryName,
        description: r.categoryDescription,
        currentAction: r.currentAction,
        riskLevel: this.assessRiskLevel(r.botCategoryName, r.currentAction),
      }));

      const hasCritical = weakCategories.some((c) => c.riskLevel === 'CRITICAL');

      return {
        securityConfigName: firstRow.securityConfigName,
        securityPolicyName: firstRow.securityPolicyName,
        policyAkamaiId: firstRow.policyAkamaiId,
        weakCategories,
        totalWeakCategories: weakCategories.length,
        severity: hasCritical ? 'CRITICAL' : 'HIGH',
        recommendation: 'Set malicious and impersonator bot categories to DENY. Configure appropriate challenges for other suspicious categories.',
      };
    });
  }

  getDeduplicationKey(finding: AkamaiBotCategoriesWeakFinding): string {
    return `akamai-bot-weak:${finding.securityConfigName}:${finding.policyAkamaiId}`;
  }
}
```

---

## Recipe Registration

Add new recipes to the recipe registry:

### `registry/recipe-registry.ts` (additions)

```typescript
// Add imports
import { CfBotManagementWeakRecipe } from '../cloudflare/cf-bot-management-weak/cf-bot-management-weak.recipe';
import { AwsWafNoLoggingRecipe } from '../aws/aws-waf-no-logging/aws-waf-no-logging.recipe';
import { AwsManagedRulesCountOverrideRecipe } from '../aws/aws-managed-rules-count-override/aws-managed-rules-count-override.recipe';
import { AzWafBroadExclusionsRecipe } from '../azure/az-waf-broad-exclusions/az-waf-broad-exclusions.recipe';
import { AkamaiBotCategoriesWeakRecipe } from '../akamai/akamai-bot-categories-weak/akamai-bot-categories-weak.recipe';

// Add to recipe array
export const ALL_RECIPES = [
  // ... existing recipes
  CfBotManagementWeakRecipe,
  AwsWafNoLoggingRecipe,
  AwsManagedRulesCountOverrideRecipe,
  AzWafBroadExclusionsRecipe,
  AkamaiBotCategoriesWeakRecipe,
];
```

---

## Common Patterns Reference

### Base Finding Recipe Interface

```typescript
export abstract class BaseFindingRecipe<TRow, TFinding> {
  abstract fetchData(): Promise<TRow[]>;
  abstract transformToFindings(rows: TRow[]): TFinding[];
  abstract getDeduplicationKey(finding: TFinding): string;
  
  async run(): Promise<TFinding[]> {
    const rows = await this.fetchData();
    return this.transformToFindings(rows);
  }
}
```

### Recipe Metadata Structure

```typescript
export interface RecipeMetadata {
  id: string;                    // Unique identifier (kebab-case)
  name: string;                  // Human-readable name
  description: string;           // Brief description
  vendor: 'cloudflare' | 'aws' | 'azure' | 'akamai';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;              // e.g., 'waf-configuration', 'bot-protection', 'visibility'
  documentation: string;         // Link to official vendor documentation
}
```

### Common Query Patterns

```typescript
// Always filter out deleted records
eq(Table.isDeleted, false)

// Join with organization context
.innerJoin(OrgTable, eq(OrgTable.id, MainTable.organizationId))

// Group findings by parent resource
const groupMap = new Map<string, Row[]>();
rows.forEach((row) => {
  const key = row.parentId;
  if (!groupMap.has(key)) groupMap.set(key, []);
  groupMap.get(key)!.push(row);
});
```

---

## Next Steps

1. **Create the recipe directory structure** for each new check
2. **Implement the repository** with the SQL query
3. **Implement the recipe class** with transformation logic
4. **Register the recipe** in the registry
5. **Add tests** for the new recipes
6. **Deploy and monitor** findings

---

*Generated by WAF Security Analysis Team - 2026-01-04*



