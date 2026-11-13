-- 0038：按扩展名回填空 MIME
--
-- 现象：iPhone 拍的 HEIC 上传后 node.mime 为空，预览返回 500「转换失败，请下载后查看」。
-- 根因不是解码能力，而是 mime 为空时预览分流把图片当"未知二进制"丢给 LibreOffice。
--
-- 为什么会有空值和 octet-stream：Content-Type 由浏览器给，不同来源差别很大——
-- iPhone Safari 传 .heic 常给空，Windows 资源管理器拖拽常给 application/octet-stream。
-- 新上传已在应用层按扩展名补全（handlers_content.go），这里处理存量数据，
-- 否则老文件永远修不好，只能重新上传一遍。
--
-- 只回填"能确定"的：扩展名与 MIME 是一一对应的那些。
-- 不猜 office（.doc 可能是 doc/xls/ppt 混淆），也不动已经有值的行。

BEGIN;

UPDATE node
   SET mime = CASE lower(ext)
                WHEN '.pdf'    THEN 'application/pdf'
                WHEN '.png'    THEN 'image/png'
                WHEN '.jpg'    THEN 'image/jpeg'
                WHEN '.jpeg'   THEN 'image/jpeg'
                WHEN '.gif'    THEN 'image/gif'
                WHEN '.webp'   THEN 'image/webp'
                WHEN '.bmp'    THEN 'image/bmp'
                WHEN '.ico'    THEN 'image/x-icon'
                WHEN '.avif'   THEN 'image/avif'
                WHEN '.heic'   THEN 'image/heic'
                WHEN '.heif'   THEN 'image/heif'
                WHEN '.svg'    THEN 'image/svg+xml'
                WHEN '.tif'    THEN 'image/tiff'
                WHEN '.tiff'   THEN 'image/tiff'
                WHEN '.mp4'    THEN 'video/mp4'
                WHEN '.m4v'    THEN 'video/mp4'
                WHEN '.mov'    THEN 'video/quicktime'
                WHEN '.webm'   THEN 'video/webm'
                WHEN '.mkv'    THEN 'video/x-matroska'
                WHEN '.mp3'    THEN 'audio/mpeg'
                WHEN '.wav'    THEN 'audio/wav'
                WHEN '.m4a'    THEN 'audio/mp4'
                WHEN '.ogg'    THEN 'audio/ogg'
                WHEN '.txt'    THEN 'text/plain; charset=utf-8'
                WHEN '.log'    THEN 'text/plain; charset=utf-8'
                WHEN '.md'     THEN 'text/markdown; charset=utf-8'
                WHEN '.csv'    THEN 'text/csv; charset=utf-8'
                WHEN '.json'   THEN 'application/json'
                WHEN '.xml'    THEN 'application/xml'
                ELSE NULL
              END
 WHERE kind = 'file'
   AND deleted_at IS NULL
   AND (mime IS NULL OR mime = '' OR mime = 'application/octet-stream')
   -- ext 列可能为空，用文件名补一次
   AND NULLIF(lower(ext), '') IS NOT NULL
   AND lower(ext) IN (
     '.pdf','.png','.jpg','.jpeg','.gif','.webp','.bmp','.ico','.avif','.heic','.heif',
     '.svg','.tif','.tiff','.mp4','.m4v','.mov','.webm','.mkv','.mp3','.wav','.m4a','.ogg',
     '.txt','.log','.md','.csv','.json','.xml'
   );

-- ext 为空的存量行：从文件名取最后一段扩展名再回填一次。
-- regexp 用「点 + 字母数字」结尾，避免把 "v1.2" 这类当扩展名。
UPDATE node
   SET mime = CASE lower(substring(name from '\.([A-Za-z0-9]{1,8})$'))
                WHEN 'pdf'  THEN 'application/pdf'
                WHEN 'png'  THEN 'image/png'
                WHEN 'jpg'  THEN 'image/jpeg'
                WHEN 'jpeg' THEN 'image/jpeg'
                WHEN 'gif'  THEN 'image/gif'
                WHEN 'webp' THEN 'image/webp'
                WHEN 'bmp'  THEN 'image/bmp'
                WHEN 'avif' THEN 'image/avif'
                WHEN 'heic' THEN 'image/heic'
                WHEN 'heif' THEN 'image/heif'
                WHEN 'svg'  THEN 'image/svg+xml'
                WHEN 'tif'  THEN 'image/tiff'
                WHEN 'tiff' THEN 'image/tiff'
                WHEN 'mp4'  THEN 'video/mp4'
                WHEN 'mov'  THEN 'video/quicktime'
                WHEN 'webm' THEN 'video/webm'
                WHEN 'mp3'  THEN 'audio/mpeg'
                WHEN 'wav'  THEN 'audio/wav'
                WHEN 'm4a'  THEN 'audio/mp4'
                WHEN 'txt'  THEN 'text/plain; charset=utf-8'
                WHEN 'log'  THEN 'text/plain; charset=utf-8'
                WHEN 'md'   THEN 'text/markdown; charset=utf-8'
                WHEN 'csv'  THEN 'text/csv; charset=utf-8'
                WHEN 'json' THEN 'application/json'
                WHEN 'xml'  THEN 'application/xml'
                ELSE NULL
              END
 WHERE kind = 'file'
   AND deleted_at IS NULL
   AND (mime IS NULL OR mime = '' OR mime = 'application/octet-stream')
   AND NULLIF(lower(ext), '') IS NULL
   AND substring(name from '\.([A-Za-z0-9]{1,8})$') IS NOT NULL;

COMMIT;
