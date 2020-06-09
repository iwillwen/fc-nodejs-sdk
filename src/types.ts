export type Region = 'cn-shanghai' | 'cn-hangzhou'| 'cn-shenzhen'
export type HTTPMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD'
export type PlainObject<T = any> = { [key: string]: T }
export type Body = Buffer | string | PlainObject

export interface EntityWithTime {
  createdTime?: string
  lastModifiedTime?: string
}

export interface FCError {
  errorCode?: string
  errorMessage?: string
}

export interface Config {
  accessKeyID?: string
  securityToken?: string
  accessKeySecret?: string
  region?: Region
  secure?: boolean
  internal?: boolean
  endpoint?: string
  timeout?: number
  headers?: PlainObject
  userAgent?: string
}

export interface ListOption {
  tags?: PlainObject
  limit?: number
  prefix?: string
  startKey?: string
  nextToken?: NextToken

  [key: string]: any
}
export type ListResult<K, T> = Record<Extract<K, string>, T> & {
  nextToken?: NextToken
}
export interface LogConfig {
  logstore?: string
  project?: string
}
export interface CreateServiceOption {
  description?: string
  logConfig?: LogConfig
  role?: string
}
export interface VPCConfig {
  securityGroupId: string
  vSwitchIds: string[]
  vpcId: string
}
export interface MountPoint {
  serverAddr: string
  mountDir: string
}
export interface NASConfig {
  userId: string
  groupId: string
  mountPoints: MountPoint[]
}
export interface Service extends EntityWithTime {
  description?: string
  internetAccess?: boolean
  logConfig?: LogConfig
  role?: string
  serviceId?: string
  serviceName: string
  vpcConfig?: VPCConfig
  nasConfig?: NASConfig
}
export type ServiceResponse = Partial<Service>
export type ServiceUpdateFields = Omit<Service, 'serviceName'>
export interface Trigger {
  invocationRole: string
  sourceArn: string
  triggerConfig: PlainObject
  triggerName: string
  triggerType: string
  qualifier?: string
}
export type TriggerResponse = Partial<Trigger & EntityWithTime>
export type TriggerUpdateFields = Pick<TriggerResponse, 'invocationRole' | 'triggerConfig' | 'qualifier'>
export interface PathConfig {
  path: string
  serviceName: string
  functionName: string
}
export interface RouteConfig {
  routes: PathConfig[]
}
export interface CertConfig {
  certName: string
  privateKey: string
  certificate: string
}
export type CustomDomainProtocol = 'HTTP' | 'HTTP,HTTPS'
export interface CustomDomainConfig {
  domainName: string
  protocol: CustomDomainProtocol
  apiVersion?: string
  routeConfig?: RouteConfig
  certConfig?: CertConfig
}
export interface CustomDomainResponse extends EntityWithTime, Omit<CustomDomainConfig, 'certConfig'> {
  serviceId?: string
}
export interface Version {
  versionId: string
  description?: string
}
export type VersionResponse = Partial<Version & EntityWithTime>
export interface Alias {
  aliasName: string
  versionId: string
  description?: string
  additionalVersionWeight: PlainObject<number>
}
export type AliasResponse = Partial<Alias & EntityWithTime>
export type AliasUpdateFields = Omit<Alias, 'versionId'>
export interface PutProvisionConfigFields {
  target: number
}
export interface ProvisionTargetResponse {
  resource: string
  target: number
}
export interface ProvisionConfigResponse extends ProvisionTargetResponse {
  current: number
}
export interface Code {
  ossBucketName?: string
  ossObjectName?: string
  zipFile?: string
}
export interface FCFunction {
  code: Code
  description?: string
  functionName: string
  handler: string
  memorySize?: number
  runtime: 'nodejs6' | 'nodejs8' | 'python2.7' | 'python3' | 'java8'
  EnvironmentVariables?: PlainObject<string>
  timeout?: number
  initializer?: string
  initializationTimeout?: number
}
export interface FunctionCodeResponse {
  checksum?: string
  url?: string
}
export interface FunctionResponse extends Partial<Omit<FCFunction, 'code' | 'initializer' | 'initializationTimeout'> & EntityWithTime> {
  functionId?: string
  codeChecksum?: string
  codeSize?: string
}
export type FunctionUpdateFields = Partial<Pick<FCFunction, 'code' | 'description' | 'handler' | 'memorySize' | 'runtime' | 'EnvironmentVariables' | 'timeout'>>
export type NextToken = string
export type InvokeResponse<T> = T
export interface ReservedCapacity extends EntityWithTime {
  instanceId?: string
  cu?: number
  deadline?: string
  isRefunded?: string
}