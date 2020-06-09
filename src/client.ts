import * as qs from 'querystring'
import SHA256 from 'crypto-js/sha256'
import MD5 from 'crypto-js/md5'
import BASE64 from 'crypto-js/enc-base64'
import fetch from 'node-fetch'
import DEBUG from 'debug'
import { Buffer } from 'buffer'

import { composeStringToSign } from './helper'
import {
  HTTPMethod,
  PlainObject,
  Body,
  Config,
  ListOption,
  CreateServiceOption,
  Service,
  ServiceResponse,
  InvokeResponse,
  FCFunction,
  FunctionResponse, 
  FunctionCodeResponse,
  FunctionUpdateFields,
  Trigger,
  TriggerResponse,
  TriggerUpdateFields,
  CustomDomainConfig,
  CustomDomainResponse,
  ListResult,
  Version,
  VersionResponse,
  Alias,
  AliasResponse,
  ReservedCapacity,
  ProvisionConfigResponse,
} from './types'

const debug = DEBUG('lambda')


function signString(source: string, secret: string) {
  const buffer = SHA256(source, secret)
  return BASE64.stringify(buffer)
}

function getServiceName(serviceName: string, qualifier?: string) {
  if (qualifier) {
    return `${serviceName}.${qualifier}`
  }

  return serviceName
}

function genUserAgent(defaultUA?: string) {
  if (defaultUA) {
    return defaultUA
  }

  if (process) {
    return `Node.js(${process.version}) OS(${process.platform}/${process.arch}) SDK`
  }

  return `FC-Node-SDK`
}


export default class Client {
  private accountid: string
  private accessKeyID: string
  private securityToken: string
  private accessKeySecret: string

  private endpoint: string
  private host: string
  private version = '2016-08-15'
  private timeout: number
  private headers: PlainObject
  private userAgent: string

  constructor(accountid: string, config: Config) {
    if (!accountid) {
      throw new TypeError('"accountid" must be passed in')
    }
    this.accountid = accountid

    if (!config) {
      throw new TypeError('"config" must be passed in')
    }

    const accessKeyID = config.accessKeyID
    if (!accessKeyID) {
      throw new TypeError('"config.accessKeyID" must be passed in')
    }

    this.accessKeyID = accessKeyID

    if (this.accessKeyID.startsWith('STS')) {
      const securityToken = config.securityToken
      if (!securityToken) {
        throw new TypeError('"config.securityToken" must be passed in for STS')
      }
      this.securityToken = securityToken
    }

    const accessKeySecret = config.accessKeySecret
    if (!accessKeySecret) {
      throw new TypeError('"config.accessKeySecret" must be passed in')
    }
    this.accessKeySecret = accessKeySecret

    const region = config.region
    if (!region) {
      throw new TypeError('"config.region" must be passed in')
    }

    const protocol = config.secure ? 'https' : 'http'

    const internal = config.internal ? '-internal' : ''

    this.endpoint = config.endpoint || `${protocol}://${accountid}.${region}${internal}.fc.aliyuncs.com`
    this.host = `${accountid}.${region}${internal}.fc.aliyuncs.com`
    this.timeout = typeof config.timeout === 'number' && Number.isFinite(config.timeout) ? config.timeout : 60000 // default is 60s
    this.headers = config.headers || {}
    const userAgent = config.userAgent
    if (userAgent) this.userAgent = userAgent
  }

  private buildHeaders() {
    const now = new Date()
    const headers: PlainObject = {
      'accept': 'application/json',
      'date': now.toUTCString(),
      'host': this.host,
      'user-agent': genUserAgent(this.userAgent),
      'x-fc-account-id': this.accountid,
    };

    if (this.securityToken) {
      headers['x-fc-security-token'] = this.securityToken
    }
    return headers
  }

  public async request<T = any>(method: HTTPMethod, path: string, query: PlainObject | undefined, body: any, headers: PlainObject = {}) {
    let url = `${this.endpoint}/${this.version}${path}`
    if (query && Object.keys(query).length > 0) {
      url = `${url}?${qs.stringify(query)}`
    }

    headers = Object.assign(this.buildHeaders(), this.headers, headers)
    let postBody: string | Buffer | null = null
    if (body) {
      debug('request body: %s', body)
      let buff: string | Buffer
      if (Buffer.isBuffer(body)) {
        buff = body
        headers['content-type'] = 'application/octet-stream'
      } else if (typeof body === 'string') {
        buff = new Buffer(body, 'utf8')
        headers['content-type'] = 'application/octet-stream'
      } else if ('function' === typeof body.pipe) {
        buff = body
        headers['content-type'] = 'application/octet-stream'
      } else {
        buff = new Buffer(JSON.stringify(body), 'utf8')
        headers['content-type'] = 'application/json'
      }

      if ('function' !== typeof body.pipe) {
        const md5 = BASE64.stringify(MD5(buff.toString('binary')))

        headers['content-length'] = buff.length
        headers['content-md5'] = md5
      }
      postBody = buff
    }

    let queriesToSign: PlainObject | null = null
    if (path.startsWith('/proxy/')) {
      queriesToSign = query || {}
    }
    const signature = Client.getSignature(this.accessKeyID, this.accessKeySecret, method, `/${this.version}${path}`, headers, queriesToSign || {})
    headers['authorization'] = signature

    debug('request headers: %j', headers)
    const res = await fetch(url, {
      method,
      timeout: this.timeout,
      headers,
      body: postBody as string | Buffer
    })

    debug('response status: %s', res.status)
    debug('response headers: %j', res.headers)
    
    const contentType: string = res.headers['content-type'] || ''

    let data: PlainObject | null = null

    if (contentType.startsWith('applicatio/json')) {
      try {
        data = await res.json()
      } catch(err) {
        // TODO: add extra message
        throw err
      }
    }

    if ((res.status < 200 || res.status >= 300) && data !== null) {
      const code = res.status
      const requestid: string = res.headers['x-fc-request-id']
      const errMsg = data.ErrorMessage || data.errorMessage || ''
      const err = new Error(`${method} ${path} failed with ${code}. requestid: ${requestid}, message: ${errMsg}.`)

      err.name = `FC${data.ErrorCode || ''}Error`;
      (err as any).code = data.ErrorCode || ''
      throw err
    }

    return {
      headers: res.headers,
      data: data as InvokeResponse<T>,
    }
  }

  /**
   * GET 请求
   *
   * @param {String} path 请求路径
   * @param {Object} query 请求中的 query 部分
   * @param {Object} headers 请求中的自定义 headers 部分
   * @return {Promise} 返回 Response
   */
  private get<T>(path: string, query?: PlainObject, headers?: PlainObject) {
    return this.request<T>('GET', path, query, null, headers)
  }

  /**
   * POST 请求
   *
   * @param {String} path 请求路径
   * @param {Buffer|String|Object} body 请求中的 body 部分
   * @param {Object} headers 请求中的自定义 headers 部分
   * @param {Object} queries 请求中的自定义 queries 部分
   * @return {Promise} 返回 Response
   */
  private post<T>(path: string, body: Body, headers: PlainObject = {}, queries: PlainObject = {}) {
    return this.request<T>('POST', path, queries, body, headers)
  }

  /**
   * PUT 请求
   *
   * @param {String} path 请求路径
   * @param {Buffer|String|Object} body 请求中的 body 部分
   * @param {Object} headers 请求中的自定义 headers 部分
   * @return {Promise} 返回 Response
   */
  private put<T>(path: string, body: Body, headers: PlainObject = {}) {
    return this.request<T>('PUT', path, undefined, body, headers)
  }

  /**
   * DELETE 请求
   *
   * @param {String} path 请求路径
   * @param {Object} query 请求中的 query 部分
   * @param {Object} headers 请求中的自定义 headers 部分
   * @return {Promise} 返回 Response
   */
  private delete<T>(path: string, query?: PlainObject, headers?: PlainObject) {
    return this.request<T>('DELETE', path, query, null, headers)
  }

  /**
   * 创建Service
   *
   * Options:
   * - description Service的简短描述
   * - logConfig log config
   * - role Service role
   *
   * @param {String} serviceName 服务名
   * @param {Object} options 选项，optional
   * @return {Promise} 返回 Object(包含headers和data属性[ServiceResponse])
   */
  public createService(serviceName: string, options: PlainObject = {}, headers?: PlainObject) {
    return this.post<ServiceResponse>('/services', Object.assign({
      serviceName,
    }, options), headers)
  }

  /**
   * 获取Service列表
   *
   * Options:
   * - limit
   * - prefix
   * - startKey
   * - nextToken
   *
   * @param {Object} options 选项，optional
   * @return {Promise} 返回 Object(包含headers和data属性[Service 列表])
   */
  public listServices(options: ListOption = {}, headers: PlainObject) {
    if (options.tags !== undefined) {
      for (const k in options.tags) {
        if (options.tags.hasOwnProperty(k)) {
          options[`tag_${k}`] = options.tags[k]
        }
      }
      delete options.tags
    }
    return this.get<ListResult<'service', Service[]>>('/services', options, headers)
  }

  /**
   * 获取service信息
   *
   * @param {String} serviceName
   * @param {Object} headers
   * @param {String} qualifier
   * @return {Promise} 返回 Object(包含headers和data属性[Service 信息])
   */
  public getService(serviceName: string, headers: PlainObject = {}, qualifier?: string) {
    return this.get<Service>(`/services/${getServiceName(serviceName, qualifier)}`, undefined, headers)
  }

  /**
   * 更新Service信息
   *
   * Options:
   * - description Service的简短描述
   * - logConfig log config
   * - role service role
   *
   * @param {String} serviceName 服务名
   * @param {Object} options 选项，optional
   * @return {Promise} 返回 Object(包含headers和data属性[Service 信息])
   */
  public updateService(serviceName: string, options: CreateServiceOption= {}, headers: PlainObject = {}) {
    return this.put<Service>(`/services/${serviceName}`, options, headers)
  }

  /**
   * 删除Service
   *
   * @param {String} serviceName
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public deleteService(serviceName: string, options: PlainObject = {}, headers?: PlainObject) {
    return this.delete<any>(`/services/${serviceName}`, options, headers);
  }

  /**
   * 创建Function
   *
   * Options:
   * - description function的简短描述
   * - code function代码
   * - functionName
   * - handler
   * - initializer
   * - memorySize
   * - runtime
   * - timeout
   * - initializationTimeout
   *
   * @param {String} serviceName 服务名
   * @param {Object} options Function配置
   * @return {Promise} 返回 Function 信息
   */
  public createFunction(serviceName: string, options: FCFunction, headers?: PlainObject) {
    options = this.normalizeParams(options) as FCFunction
    return this.post<FunctionResponse>(`/services/${serviceName}/functions`, options, headers)
  }

  private normalizeParams(opts: Partial<FCFunction & FunctionUpdateFields>) {
    if (opts.functionName) {
      opts.functionName = String(opts.functionName)
    }

    if (opts.runtime) {
      opts.runtime = String(opts.runtime) as FCFunction['runtime']
    }

    if (opts.handler) {
      opts.handler = String(opts.handler)
    }

    if (opts.initializer) {
      opts.initializer = String(opts.initializer)
    }

    if (opts.memorySize) {
      opts.memorySize = parseInt(opts.memorySize as any, 10)
    }

    if (opts.timeout) {
      opts.timeout = parseInt(opts.timeout as any, 10)
    }

    if (opts.initializationTimeout) {
      opts.initializationTimeout = parseInt(opts.initializationTimeout as any, 10)
    }
    return opts
  }

  /**
   * 获取Function列表
   *
   * Options:
   * - limit
   * - prefix
   * - startKey
   * - nextToken
   *
   * @param {String} serviceName
   * @param {Object} options 选项，optional
   * @param {Object} headers
   * @param {String} qualifier 可选
   * @return {Promise} 返回 Object(包含headers和data属性[Function列表])
   */
  public listFunctions(serviceName: string, options: ListOption = {}, headers: PlainObject = {}, qualifier?: string) {
    return this.get<ListResult<'functions', FunctionResponse[]>>(`/services/${getServiceName(serviceName, qualifier)}/functions`, options, headers)
  }

  /**
   * 获取Function信息
   *
   * @param {String} serviceName
   * @param {String} functionName
   * @param {Object} headers
   * @param {String} qualifier 可选
   * @return {Promise} 返回 Object(包含headers和data属性[Function信息])
   */
  public getFunction(serviceName: string, functionName: string, headers: PlainObject = {}, qualifier?: string) {
    return this.get<FunctionResponse>(`/services/${getServiceName(serviceName, qualifier)}/functions/${functionName}`, undefined, headers)
  }

  /**
   * 获取Function Code信息
   *
   * @param {String} serviceName
   * @param {String} functionName
   * @param {Object} headers
   * @param {String} qualifier 可选
   * @return {Promise} 返回 Object(包含headers和data属性[Function信息])
   */
  public getFunctionCode(serviceName: string, functionName: string, headers: PlainObject = {}, qualifier?: string) {
    return this.get<FunctionCodeResponse>(`/services/${getServiceName(serviceName, qualifier)}/functions/${functionName}/code`, headers)
  }

  /**
   * 更新Function信息
   *
   * @param {String} serviceName
   * @param {String} functionName
   * @param {Object} options Function配置，见createFunction
   * @return {Promise} 返回 Object(包含headers和data属性[Function信息])
   */
  public updateFunction(serviceName: string, functionName: string, options: FunctionUpdateFields, headers: PlainObject = {}) {
    options = this.normalizeParams(options) as FunctionUpdateFields
    const path = `/services/${serviceName}/functions/${functionName}`
    return this.put<FunctionResponse>(path, options, headers)
  }

  /**
   * 删除Function
   *
   * @param {String} serviceName
   * @param {String} functionName
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public deleteFunction(serviceName: string, functionName: string, options: PlainObject = {}, headers?: PlainObject) {
    const path = `/services/${serviceName}/functions/${functionName}`
    return this.delete<any>(path, options, headers)
  }

  /**
   * 调用Function
   *
   * @param {String} serviceName
   * @param {String} functionName
   * @param {Object} event event信息
   * @param {Object} headers
   * @param {String} qualifier
   * @return {Promise} 返回 Object(包含headers和data属性[返回Function的执行结果])
   */
  public invokeFunction<T>(serviceName: string, functionName: string, event: string | Buffer, headers?: PlainObject, qualifier?: string) {
    if (event && typeof event !== 'string' && !Buffer.isBuffer(event)) {
      throw new TypeError('"event" must be String or Buffer')
    }

    const path = `/services/${getServiceName(serviceName, qualifier)}/functions/${functionName}/invocations`
    return this.post<T>(path, event, headers, undefined)
  }

  /**
   * 创建Trigger
   *
   * Options:
   * - invocationRole
   * - sourceArn
   * - triggerType
   * - triggerName
   * - triggerConfig
   * - qualifier
   *
   * @param {String} serviceName 服务名
   * @param {String} functionName 服务名
   * @param {Object} options Trigger配置
   * @param {Object} headers
   * @return {Promise} 返回 Object(包含headers和data属性[Trigger信息])
   */
  public createTrigger(serviceName: string, functionName: string, options: Trigger, headers: PlainObject = {}) {
    const path = `/services/${serviceName}/functions/${functionName}/triggers`
    return this.post<TriggerResponse>(path, options, headers)
  }

  /**
   * 获取Trigger列表
   *
   * Options:
   * - limit
   * - prefix
   * - startKey
   * - nextToken
   *
   * @param {String} serviceName
   * @param {String} functionName
   * @param {Object} options 选项，optional
   * @return {Promise} 返回 Object(包含headers和data属性[Trigger列表])
   */
  public listTriggers(serviceName: string, functionName: string, options: PlainObject = {}, headers?: PlainObject) {
    const path = `/services/${serviceName}/functions/${functionName}/triggers`
    return this.get<ListResult<'triggers', TriggerResponse[]>>(path, options, headers)
  }

  /**
   * 获取Trigger信息
   *
   * @param {String} serviceName
   * @param {String} functionName
   * @param {String} triggerName
   * @return {Promise} 返回 Object(包含headers和data属性[Trigger信息])
   */
  public getTrigger(serviceName: string, functionName: string, triggerName: string, headers?: PlainObject) {
    const path = `/services/${serviceName}/functions/${functionName}/triggers/${triggerName}`
    return this.get<TriggerResponse>(path, undefined, headers)
  }

  /**
   * 更新Trigger信息
   *
   * @param {String} serviceName
   * @param {String} functionName
   * @param {String} triggerName
   * @param {Object} options Trigger配置，见createTrigger
   * @param {Object} headers
   * @return {Promise} 返回 Object(包含headers和data属性[Trigger信息])
   */
  public updateTrigger(serviceName: string, functionName: string, triggerName: string, options: TriggerUpdateFields = {}, headers?: PlainObject) {
    const path = `/services/${serviceName}/functions/${functionName}/triggers/${triggerName}`
    return this.put<TriggerResponse>(path, options, headers)
  }

  /**
   * 删除Trigger
   *
   * @param {String} serviceName
   * @param {String} functionName
   * @param {String} triggerName
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public deleteTrigger(serviceName: string, functionName: string, triggerName: string, options: PlainObject = {}, headers?: PlainObject) {
    const path = `/services/${serviceName}/functions/${functionName}/triggers/${triggerName}`
    return this.delete<any>(path, options, headers)
  }

  /**
   * 创建CustomDomain
   *
   * Options:
   * - protocol
   * - routeConfig
   *
   * @param {String} domainName 域名
   * @param {Object} options 选项，optional
   * @return {Promise} 返回 Object(包含headers和data属性[CustomDomainResponse])
   */
  public createCustomDomain(domainName: string, options: Partial<CustomDomainConfig> = {}, headers?: PlainObject) {
    return this.post<CustomDomainResponse>('/custom-domains', Object.assign({
      domainName,
    }, options), headers)
  }

  /**
   * 获取CustomDomain列表
   *
   * Options:
   * - limit
   * - prefix
   * - startKey
   * - nextToken
   *
   * @param {Object} options 选项，optional
   * @return {Promise} 返回 Object(包含headers和data属性[CustomDomain 列表])
   */
  public listCustomDomains(options: ListOption = {}, headers?: PlainObject) {
    return this.get<ListResult<'services', CustomDomainResponse[]>>('/custom-domains', options, headers)
  }

  /**
   * 获取CustomDomain信息
   *
   * @param {String} domainName
   * @return {Promise} 返回 Object(包含headers和data属性[CustomDomain 信息])
   */
  public getCustomDomain(domainName: string, headers?: PlainObject) {
    return this.get<CustomDomainResponse>(`/custom-domains/${domainName}`, undefined, headers)
  }

  /**
   * 更新CustomDomain信息
   *
   * Options:
   * - protocol
   * - routeConfig
   *
   * @param {String} domainName
   * @param {Object} options 选项，optional
   * @return {Promise} 返回 Object(包含headers和data属性[Service 信息])
   */
  public updateCustomDomain(domainName: string, options: Partial<Pick<CustomDomainConfig, 'protocol' | 'routeConfig'>> = {}, headers?: PlainObject) {
    return this.put<CustomDomainResponse>(`/custom-domains/${domainName}`, options, headers)
  }

  /**
   * 删除CustomDomain
   *
   * @param {String} domainName
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public deleteCustomDomain(domainName: string, options: PlainObject = {}, headers?: PlainObject) {
    return this.delete<any>(`/custom-domains/${domainName}`, options, headers)
  }

  /**
   * 创建 version
   *
   * @param {String} serviceName
   * @param {String} description
   * @param {Object} headers
   * @return {Promise} 返回 Object(包含headers和data属性[Version 信息])
   */
  public publishVersion(serviceName: string, description: string, headers?: PlainObject) {
    const body: Partial<Version> = {}
    if (description) {
      body.description = description
    }
    return this.post<VersionResponse>(`/services/${serviceName}/versions`, body, headers || {})
  }

  /**
   * 列出 version
   *
   * Options:
   * - limit
   * - nextToken
   * - startKey
   * - direction
   *
   * @param {String} serviceName
   * @param {Object} options
   * @param {Object} headers
   * @return {Promise} 返回 Object(包含headers和data属性[Version 信息])
   */
  public listVersions(serviceName: string, options: ListOption = {}, headers?: PlainObject) {
    return this.get<ListResult<'versions', VersionResponse[]> & { direction?: string }>(`/services/${serviceName}/versions`, options, headers)
  }

  /**
   * 删除 version
   *
   * @param {String} serviceName
   * @param {String} versionId
   * @param {Object} headers
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public deleteVersion(serviceName: string, versionId: string, headers: PlainObject = {}) {
    return this.delete<any>(`/services/${serviceName}/versions/${versionId}`, undefined, headers)
  }


  /**
   * 创建 Alias
   *
   * Options:
   * - description
   * - additionalVersionWeight
   *
   * @param {String} serviceName
   * @param {String} aliasName
   * @param {String} versionId
   * @param {Object} options
   * @param {Object} headers
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public createAlias(serviceName: string, aliasName: string, versionId: string, options: Partial<Alias> = {}, headers = {}) {
    options.aliasName = aliasName
    options.versionId = versionId

    return this.post<AliasResponse>(`/services/${serviceName}/aliases`, options, headers)
  }

  /**
   * 删除 Alias
   *
   * @param {String} serviceName
   * @param {String} aliasName
   * @param {String} headers
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public deleteAlias(serviceName: string, aliasName: string, headers: PlainObject = {}) {
    return this.delete<any>(`/services/${serviceName}/aliases/${aliasName}`, undefined, headers)
  }

  /**
   * 列出 alias
   *
   * Options:
   * - limit
   * - nextToken
   * - prefix
   * - startKey
   *
   * @param {String} serviceName
   * @param {Object} options
   * @param {Object} headers
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public listAliases(serviceName: string, options: ListOption = {}, headers?: PlainObject) {
    return this.get<ListResult<'aliases', AliasResponse[]>>(`/services/${serviceName}/aliases`, options, headers)
  }

  /**
   * 获得 alias
   *
   * @param {String} serviceName
   * @param {String} aliasName
   * @param {Object} headers
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public getAlias(serviceName: string, aliasName: string, headers?: PlainObject) {
    return this.get<AliasResponse>(`/services/${serviceName}/aliases/${aliasName}`, undefined, headers)
  }

  /**
   * 更新 alias
   *
   * Options:
   * - description
   * - additionalVersionWeight
   *
   * @param {String} serviceName
   * @param {String} aliasName
   * @param {String} versionId
   * @param {Object} options
   * @param {Object} headers
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public updateAlias(serviceName: string, aliasName: string, versionId: string, options: Partial<Alias> = {}, headers?: PlainObject) {
    if (versionId) {
      options.versionId = versionId
    }
    return this.put<AliasResponse>(`/services/${serviceName}/aliases/${aliasName}`, options, headers)
  }

  /**
   * 给fc资源打tag
   *
   * @param {String} resourceArn Resource ARN. Either full ARN or partial ARN.
   * @param {Object} tags  A list of tag keys. At least 1 tag is required. At most 20. Tag key is required, but tag value is optional.
   * @param {Object} options
   * @param {Object} headers
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public tagResource(resourceArn: string, tags: PlainObject<string>, options: PlainObject = {}, headers?: PlainObject) {
    options.resourceArn = resourceArn
    options.tags = tags

    return this.post<any>('/tag', options, headers)
  }

  /**
   * 给fc资源取消tag
   *
   * @param {String} resourceArn Resource ARN. Either full ARN or partial ARN.
   * @param {Object} tagkeys  A list of tag keys. At least 1 tag key is required if all=false. At most 20.
   * @param {Boolean} all Remove all tags at once. Default value is false. Accept value: true or false.
   * @param {Object} options
   * @param {Object} headers
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public untagResource(resourceArn: string, tagKeys: string[], all = false, options: PlainObject = {}, headers?: PlainObject) {
    options.resourceArn = resourceArn
    options.tagKeys = tagKeys
    options.all = all
    return this.request<any>('DELETE', '/tag', undefined, options, headers)
  }

  /**
   * 获取某个资源的所有tag
   *
   * @param {Object} options
   * @param {Object} headers
   * @return {Promise} 返回 Object(包含headers和data属性)
   */
  public getResourceTags(options: { resourceArn?: string } = {}, headers?: PlainObject) {
    return this.get<{
      resourceArn?: string,
      tags?: PlainObject<string>
    }>('/tag', options, headers)
  }

  /**
   * 获取reservedCapacity列表
   *
   * Options:
   * - limit
   * - nextToken
   *
   * @param {Object} options 选项，optional
   * @return {Promise} 返回 Object(包含headers和data属性[reservedCapacities 列表])
   */
  public listReservedCapacities(options?: ListOption, headers?: PlainObject) {
    return this.get<ListResult<'reservedCapacities', ReservedCapacity[]>>('/reservedCapacities', options, headers)
  }

  /**
   * 获取账号下的 provisionConfigs 列表
   *
   * Options:
   * - limit
   * - nextToken
   * - serviceName
   * - qualifier
   *
   * @param {Object} options 选项，optional
   * @return {Promise} 返回 Object(包含 headers 和 data 属性[provisionConfigs 列表])
   */
  public listProvisionConfigs(options: ListOption = {}, headers?: PlainObject) {
    return this.get<ListResult<'provisionConfigs', ProvisionConfigResponse[]>>('/provision-configs', options, headers)
  }

  /**
   * 获取单个函数的 provisionConfig
   *
   * @param {String} serviceName
   * @param {String} functionName
   * @param {Object} headers
   * @param {String} qualifier 可选
   * @return {Promise} 返回 Object(包含 headers 和 data 属性[provisionConfig 信息])
   */
  public getProvisionConfig(serviceName: string, functionName: string, qualifier?: string, headers?: PlainObject) {
    return this.get<ProvisionConfigResponse>(`/services/${getServiceName(serviceName, qualifier)}/functions/${functionName}/provision-config`, undefined, headers)
  }

  /**
   * 更新单个函数的 provisionConfig
   *
   * @param {String} serviceName
   * @param {String} functionName
   * @param {Object} headers
   * @param {String} qualifier 可选
   * @return {Promise} 返回 Object(包含 headers 和 data 属性[provisionConfig 信息])
   */
  public putProvisionConfig(serviceName: string, functionName: string, qualifier?: string, options: PlainObject = {}, headers?: PlainObject) {
    return this.put<ProvisionConfigResponse>(`/services/${getServiceName(serviceName, qualifier)}/functions/${functionName}/provision-config`, options, headers)
  }

  /**
   * 获得Header 签名
   *
   * @param {String} accessKeyID
   * @param {String} accessKeySecret
   * @param {String} method : GET/POST/PUT/DELETE/HEAD
   * @param {String} path
   * @param {json} headers : {headerKey1 : 'headValue1'}
   */
  private static getSignature(accessKeyID: string, accessKeySecret: string, method: string, path: string, headers: PlainObject<string>, queries: PlainObject) {
    const stringToSign = composeStringToSign(method, path, headers, queries)
    debug('stringToSign: %s', stringToSign)
    const sign = signString(stringToSign, accessKeySecret)
    return `FC ${accessKeyID}:${sign}`
  }
}