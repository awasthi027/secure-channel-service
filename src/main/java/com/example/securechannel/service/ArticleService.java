package com.example.securechannel.service;

import com.example.securechannel.entity.ArticleEntity;
import com.example.securechannel.exception.BadRequestException;
import com.example.securechannel.model.Article;
import com.example.securechannel.repository.ArticleRepository;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class ArticleService {

    private final ArticleRepository articleRepository;

    public ArticleService(ArticleRepository articleRepository) {
        this.articleRepository = articleRepository;
    }

    public Article create(String title, String description) {
        ArticleEntity entity = new ArticleEntity();
        entity.setTitle(title);
        entity.setDescription(description);
        ArticleEntity saved = articleRepository.save(entity);
        return entityToModel(saved);
    }

    public Article getById(long id) {
        return articleRepository.findById(id)
                .map(this::entityToModel)
                .orElseThrow(() -> new BadRequestException("Article not found"));
    }

    public List<Article> getAll() {
        return articleRepository.findAll().stream()
                .map(this::entityToModel)
                .toList();
    }

    private Article entityToModel(ArticleEntity entity) {
        return new Article(entity.getId(), entity.getTitle(), entity.getDescription());
    }
}

