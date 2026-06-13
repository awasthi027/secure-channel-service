package com.example.securechannel.web;

import com.example.securechannel.api.ArticleRequest;
import com.example.securechannel.api.ArticleResponse;
import com.example.securechannel.model.Article;
import com.example.securechannel.service.ArticleService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/articles")
public class ArticleController {

    private final ProtectedRequestVerifier protectedRequestVerifier;
    private final ArticleService articleService;

    public ArticleController(
            ProtectedRequestVerifier protectedRequestVerifier,
            ArticleService articleService) {
        this.protectedRequestVerifier = protectedRequestVerifier;
        this.articleService = articleService;
    }

    @PostMapping
    public ArticleResponse createArticle(
            @Valid @RequestBody ArticleRequest request,
            HttpServletRequest httpRequest) {
        protectedRequestVerifier.verify(httpRequest);

        Article article = articleService.create(request.title(), request.description());
        return new ArticleResponse(article.id(), article.title(), article.description());
    }

    @GetMapping
    public List<ArticleResponse> getAllArticles(HttpServletRequest httpRequest) {
        protectedRequestVerifier.verify(httpRequest);

        return articleService.getAll().stream()
                .map(article -> new ArticleResponse(article.id(), article.title(), article.description()))
                .toList();
    }

    @GetMapping("/{id}")
    public ArticleResponse getArticle(
            @PathVariable long id,
            HttpServletRequest httpRequest) {
        protectedRequestVerifier.verify(httpRequest);

        Article article = articleService.getById(id);
        return new ArticleResponse(article.id(), article.title(), article.description());
    }
}

