// Package migrations 以嵌入文件的方式提供 SQL 迁移脚本。
//
// 为什么内嵌而不是运行时读目录：
//  1. 单二进制交付，部署时不需要额外拷贝 SQL 文件；
//  2. 迁移内容与二进制版本严格绑定，避免"二进制是新的、脚本是旧的"这类漂移。
package migrations

import "embed"

// Files 是全部迁移脚本，按文件名升序执行。
//
//go:embed *.sql
var Files embed.FS
