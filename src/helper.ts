import * as url from 'url'
import { PlainObject } from './types'

function buildCanonicalHeaders(headers: PlainObject<string>, prefix: string) {
  let list: string[] = []
  const keys = Object.keys(headers)

  const fcHeaders: PlainObject<string> = {}
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i]

    const lowerKey = key.toLowerCase().trim()
    if (lowerKey.startsWith(prefix)) {
      list.push(lowerKey)
      fcHeaders[lowerKey] = headers[key]
    }
  }
  list = list.sort()

  let canonical = ''
  for (let i = 0; i < list.length; i++) {
    const key = list[i]
    canonical += `${key}:${fcHeaders[key]}\n`
  }

  return canonical
}


export function composeStringToSign(method: string, path: string, headers: PlainObject<string>, queries?: PlainObject<string | string[]>) {
  const contentMD5 = headers['content-md5'] || ''
  const contentType = headers['content-type'] || ''
  const date = headers['date']
  const signHeaders = buildCanonicalHeaders(headers, 'x-fc-')

  const u = url.parse(path)
  const pathUnescaped = decodeURIComponent(u.pathname || '/')
  let str = `${method}\n${contentMD5}\n${contentType}\n${date}\n${signHeaders}${pathUnescaped}`

  if (queries) {
    let params: string[] = []
    Object.keys(queries).forEach(key => {
      const values = queries[key]
      const type = typeof values
      if (type === 'string') {
        params.push(`${key}=${values}`)
        return
      }
      if (Array.isArray(values)) {
        values.forEach(value => params.push(`${key}=${value}`))
      }
    })
    params = params.sort()
    str += '\n' + params.join('\n')
  }
  return str
}
