const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const webSocket = require('ws')

// Criando a aplicação Express
const app = express();




// Usando o middleware CORS para permitir requisições de outras origens
const corsOptions = {
    origin: "*", // Adicione o IP do seu celular ou o IP da máquina que está hospedando o frontend
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));

// Middleware para analisar JSON no corpo das requisições
app.use(express.json());

// Conectando ao MongoDB
mongoose.connect('mongodb://localhost:27017/Projeto2')
  .then(() => console.log('Conectado ao MongoDB!'))
  .catch(err => console.error('Erro ao conectar:', err));

  const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    imgUrlProfile: { type: String },
    imgBannerProfile: { type: String },
    inscritos: { type: Number, default: 0 },
    UserInscritos: {type: Array},
    UserCanaisInscritos: {type: Array},
    UserLogin: {type: String},  
    Inscriçoes: {type: Number},
    Links: {type: Object},
    VideosUsers: [
      {
        ImgUrlVideo: { type: String },
        videoId: { type: String },
        title: { type: String },
        description: { type: String },
        views: { type: String },
        likes: { type: String },
        dislikes: { type: Number },
        comments: { type: Number },
        category: [String]
      }
    ]
  });
  UserSchema.pre('save', function(next) {
    if (this.isModified('username')) {
        this.username = this.username.toLowerCase();  // Converte o username para minúsculas
    }
    next();  // Continua o processo de salvamento
});

  module.exports = mongoose.model('User', UserSchema);


const User = mongoose.model('User', UserSchema);

const JWT_SECRET = 'RobsonToken';



// Rota de cadastro
app.post('/cadastro', async(req, res) => {
    const { username, password, UserLogin } = req.body;

    if (!username || !password || !UserLogin) {
        return res.status(400).json({ error: 'Por favor, preencha todos os campos!' });
    }

    const userExists = await User.findOne({ username });
    if (userExists) {
        return res.status(400).json({ error: 'Usuário já existe!' });
    }

    try {
        const newUser = new User({
            username,
            password,
            UserLogin,
            UserInscritos: [],
            UserCanaisInscritos: [],
            VideosUsers: [],
            imgUrlProfile: '',
            imgBannerProfile: ''
        });

        await newUser.save();

        const token = jwt.sign({ userId: newUser._id }, JWT_SECRET);

        return res.status(201).json({ token});
    } catch (err) {
        console.log(err);
        return res.status(500).json({ error: 'Erro ao cadastrar usuário' });
    }
});

// Rota de login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Por favor, preencha todos os campos!' });
    }

    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(400).json({ error: "Usuário não encontrado" });
        }

        if (user.password !== password) {
            return res.status(400).json({ error: 'Senha incorreta' });
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET);

        return res.status(200).json({ message: "Login realizado com sucesso", token });
    } catch (err) {
        console.log(err);
        return res.status(500).json({ error: 'Erro ao realizar login' });
    }
});

// Rota para obter dados do usuário autenticado
app.get('/user', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1]; // Extrair token

    // Caso não tenha token, retorne todos os usuários
    if (!token) {
        const users = await User.find().select('username')
        
        return res.status(200).json(users)
    }

    // Verificação do token
    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (!decoded || !decoded.userId) {
            return res.status(401).json({ error: 'Token inválido' });
        }

        // Busca o usuário no banco de dados
        const user = await User.findById(decoded.userId);

        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        // Verifica se o usuário tem canais inscritos
        const response = {
            username: user.username,
            UserLogin: user.UserLogin,
            ImgUrl: user.imgUrlProfile,
            ImgBanner: user.imgBannerProfile,
            Inscrito: user.inscritos, // Se o campo "inscritos" existir
        };

        // Se o usuário tiver canais inscritos, retorne os dados relacionados
        if (user.UserCanaisInscritos && user.UserCanaisInscritos.length > 0) {
            const inscritos = await User.find({ UserLogin: { $in: user.UserCanaisInscritos } }).select("imgUrlProfile VideosUsers UserLogin");
            response.inscritosDetalhados = inscritos; // Adicionando detalhes dos canais inscritos
            console.log(inscritos)
        }

        return res.status(200).json(response);
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Erro ao verificar o token' });
    }
});

app.get('/user-perfil-Videos/:name', async (req, res) => {
    const { name } = req.params;

    

    try {
        // Buscando o usuário pelo nome de usuário
        const user = await User.findOne({ UserLogin: name });

        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        return res.status(200).json({
            videosUsers: user.VideosUsers
        });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Erro ao buscar vídeos do usuário' });
    }
});



    app.get('/user-perfil-Data/:name', async (req, res) => {
        const {name} = req.params
    
        try {
            const user = await User.findOne({ UserLogin: { $regex: new RegExp(`^${name}$`, 'i') } });


            if(!user) {
                return res.status(400).json({error: 'Usuário não encontrado'})
            }

        return res.status(200).json({
            username: user.username,
            imgUrlProfile: user.imgUrlProfile,
            imgBannerProfile: user.imgBannerProfile,
            inscrito: user.inscritos,
            videosUsers: user.VideosUsers,
            userLogin: user.UserLogin,
            Links: user.Links
            
        })
        } catch(e) {
            console.log(e)
        }
    });
app.get('/user-pefil-Search/:name', async (req, res) => {

    const {name} = req.params


    if(!name) {
        return res.status(400).json({error: 'Parametro obrigatorio'})
    }

    try {
        const user = await User.find({
            $or: [
                { UserLogin: { $regex: name, $options: "i" } }, // Busca pelo nome do usuário
                { "VideosUsers.title": { $regex: name, $options: "i" } } // Busca pelo título do vídeo
            ]
        });
        if(!user) {
            return res.status(400).json({error: 'Usuário não encontrado'})
        }


        const response = user.map(user => ({
            username: user.username,
            imgUrlProfile: user.imgUrlProfile,
            imgBannerProfile: user.imgBannerProfile,
            inscrito: user.inscritos,
            videosUsers: user.VideosUsers,
            userLogin: user.UserLogin,
            Links: user.Links
        }))

        return res.status(200).json(response)
    } catch (err) {
        console.error(err)
        return res.status(500).json({error: 'Error ao buscar Usuarios'})
    }


})
  

app.get('/verifyInscrito', async (req, res) => {
   const {userLogado, canalUser} = req.query


   if(!userLogado || !canalUser){
    return res.status(400).json({error: "usuario ou canal nao fornecido"})
   }


    try {
        const user = await User.findOne({username: userLogado})
        const Canal = await User.findOne({UserLogin: canalUser})


       

        if(!user || !Canal){
            return res.status(404).json({error: "Usuario ou canal não encontrado"})
        }
       
        if(Canal.UserInscritos.includes(user.username)) {
            return res.status(200).json({inscrito: true})
        } 



        await user.save()

        return res.status(200).json({inscrito: false})
        
    } catch(err) {
        return res.status(500).json({error: "Error ao verifica Inscriçao"})
    }

})

app.get('/Inscreve', async (req, res) => {
    const { userLogado, canalUser } = req.query;


    // Verificar se ambos os parâmetros foram fornecidos
    if (!userLogado || !canalUser) {
        return res.status(400).json({ error: "Todos os campos são obrigatórios" });
    }

    try {
        // Encontrar o usuário e o canal no banco de dados
        const user = await User.findOne({ username: userLogado });
        const canal = await User.findOne({ UserLogin: canalUser });

        // Verificar se o usuário e o canal existem
        if (!user || !canal) {
            return res.status(404).json({ error: "Usuário ou canal não encontrado" });
        }

        // Inicializar os arrays de inscritos, caso não existam
        if (!canal.UserInscritos) canal.UserInscritos = [];
        if (!user.UserCanaisInscritos) user.UserCanaisInscritos = [];

        // Verificar se o usuário já está inscrito no canal
        const isInscrito = canal.UserInscritos.includes(user.username);

        if (isInscrito) {
            // Se já estiver inscrito, remove a inscrição
            canal.UserInscritos = canal.UserInscritos.filter(v => v !== user.UserLogin);
            user.UserCanaisInscritos = user.UserCanaisInscritos.filter(v => v !== canal.UserLogin);

            // Salvar as alterações
            await Promise.all([canal.save(), user.save()]);

            return res.status(200).json({ inscrito: false });
        }

        // Caso contrário, inscrever o usuário no canal
        user.UserCanaisInscritos.push(canal.UserLogin);
        canal.UserInscritos.push(user.UserLogin);

        // Salvar as alterações
        await Promise.all([canal.save(), user.save()]);

        return res.status(200).json({ inscrito: true });

    } catch (err) {
        console.log(err);
        return res.status(500).json({ error: "Erro ao verificar inscrição" });
    }
});
    
app.post('/adicionaVideos', async (req, res) => {
    
    const {username, title, imgUrlVideo, videoId, likes, category} = req.body

    if(!username || !title || !imgUrlVideo || !videoId || !likes || !category) {
        return res.status(400).json({error: "Todos os campos são obrigatorios"})
    }
    
    try {
        const user = await User.findOne({username: username})

        if(!user) {
            return res.status(404).json({error: "Usuario não encontrado"})
        }

        if(!user.VideosUsers){
            user.VideosUsers = []
        }

        const videoExist = user.VideosUsers.some(video => video.videoId === videoId)

        if(videoExist) {
            return res.status(400).json({error: "Video já adicionado"})
        }

        user.VideosUsers.push({
            title: title,
            ImgUrlVideo: imgUrlVideo,
            videoId: videoId,
            likes: likes,
            category: category
        })


        await user.save()

        return res.status(201).json({mensagem: "Video adicionado com sucesso"})

    } catch (erro) {
        console.log(erro)
        return res.status(500).json({error: "Error ao adicionar video"})
    }
})

app.delete('/remover', async (req, res) => {
    const {username, videoId} = req.body

    if(!username || !videoId) {
        return res.status(400).json({error: "Todos os campos são obrigatorios"})
    }

    try {
        const user = await User.findOne({username: username})


        if(!user)  {
            return res.status(404).json({error: "Usuario não encontrado"})
        }

        const Videoatualizado = user.VideosUsers.filter(video => video.videoId !== videoId)

        if(Videoatualizado.length === user.VideosUsers.length) {
            return res.status(404).json({error: "Video não encontrado"})
        }
        
        user.VideosUsers = Videoatualizado
        await user.save()

        return res.status(200).json({mensagem: "Video removido com sucesso"})
    } catch (err) {
        console.log(err)
        return res.status(500).json({error: "Error ao remover video"})
    }
    
})

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});