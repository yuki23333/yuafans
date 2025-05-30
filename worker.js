// 配置
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = '123456';
const JWT_SECRET = 'your-jwt-secret-key'; // 请更改为随机字符串
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const MAX_IMAGE_SIZE = 5 * 1024 * 1024; // 5MB

// 工具函数
function generateToken() {
    return btoa(Math.random().toString(36) + Date.now().toString(36));
}

function verifyToken(token) {
    try {
        const [header, payload, signature] = token.split('.');
        const decodedPayload = JSON.parse(atob(payload));
        return decodedPayload.exp > Date.now() / 1000;
    } catch {
        return false;
    }
}

// 处理图片上传
async function uploadImage(file) {
    // 验证文件类型
    if (!ALLOWED_IMAGE_TYPES.includes(file.type)) {
        throw new Error('不支持的图片格式');
    }

    // 验证文件大小
    if (file.size > MAX_IMAGE_SIZE) {
        throw new Error('图片大小超过限制');
    }

    // 生成唯一文件名
    const extension = file.type.split('/')[1];
    const filename = `${generateToken()}.${extension}`;

    // 上传到 R2
    await IMAGES.put(filename, await file.arrayBuffer(), {
        httpMetadata: {
            contentType: file.type,
            cacheControl: 'public, max-age=31536000'
        }
    });

    // 返回图片URL
    return `https://pub-${IMAGES.bucket}.r2.dev/${filename}`;
}

// 处理CORS
function handleCORS(request) {
    if (request.method === 'OPTIONS') {
        return new Response(null, {
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'Access-Control-Max-Age': '86400',
            },
        });
    }
}

// 处理认证
async function handleAuth(request) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return false;
    }
    const token = authHeader.split(' ')[1];
    return verifyToken(token);
}

// 主处理函数
async function handleRequest(request) {
    // 处理CORS
    if (request.method === 'OPTIONS') {
        return handleCORS(request);
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // 公开API
    if (path === '/api/questions' && request.method === 'POST') {
        try {
            const formData = await request.formData();
            const content = formData.get('content');
            const image = formData.get('image');

            if (!content) {
                return new Response(JSON.stringify({ error: '内容不能为空' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            let imageUrl = null;
            if (image) {
                try {
                    imageUrl = await uploadImage(image);
                } catch (error) {
                    return new Response(JSON.stringify({ error: error.message }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
            }

            // 存储问题
            const question = {
                id: generateToken(),
                content,
                image: imageUrl,
                status: 'pending',
                createdAt: new Date().toISOString(),
                likes: 0,
                dislikes: 0
            };

            await QUESTIONS.put(question.id, JSON.stringify(question));
            return new Response(JSON.stringify({ success: true }), {
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (error) {
            return new Response(JSON.stringify({ error: '提交失败' }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    if (path === '/api/questions' && request.method === 'GET') {
        const questions = [];
        const list = await QUESTIONS.list();
        
        for (const key of list.keys) {
            const question = JSON.parse(await QUESTIONS.get(key.name));
            if (question.status === 'approved') {
                questions.push(question);
            }
        }

        return new Response(JSON.stringify(questions), {
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // 管理员API
    if (path === '/api/admin/login' && request.method === 'POST') {
        const { username, password } = await request.json();
        
        if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
            const token = generateToken();
            const payload = {
                exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60), // 24小时过期
                username
            };
            
            const tokenString = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })) + '.' +
                              btoa(JSON.stringify(payload)) + '.' +
                              btoa(JWT_SECRET);

            return new Response(JSON.stringify({ token: tokenString }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }

        return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // 需要认证的API
    if (!await handleAuth(request)) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    if (path === '/api/admin/questions' && request.method === 'GET') {
        const questions = [];
        const list = await QUESTIONS.list();
        
        for (const key of list.keys) {
            const question = JSON.parse(await QUESTIONS.get(key.name));
            questions.push(question);
        }

        return new Response(JSON.stringify(questions), {
            headers: { 'Content-Type': 'application/json' }
        });
    }

    if (path.match(/^\/api\/admin\/questions\/[^/]+\/approve$/) && request.method === 'POST') {
        const questionId = path.split('/')[4];
        const question = JSON.parse(await QUESTIONS.get(questionId));
        
        if (question) {
            question.status = 'approved';
            await QUESTIONS.put(questionId, JSON.stringify(question));
            return new Response(JSON.stringify({ success: true }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    if (path.match(/^\/api\/admin\/questions\/[^/]+\/archive$/) && request.method === 'POST') {
        const questionId = path.split('/')[4];
        const question = JSON.parse(await QUESTIONS.get(questionId));
        
        if (question) {
            question.status = 'archived';
            await QUESTIONS.put(questionId, JSON.stringify(question));
            return new Response(JSON.stringify({ success: true }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    return new Response(JSON.stringify({ error: 'Not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
    });
}

// 启动Worker
addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
}); 